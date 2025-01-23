// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>

#include "builder/waf_builder.hpp"
#include "context.hpp"
#include "ddwaf.h"
#include "log.hpp"
#include "obfuscator.hpp"
#include "parameter.hpp"
#include "ruleset_info.hpp"
#include "utils.hpp"
#include "version.hpp"
#include "waf.hpp"

#if DDWAF_COMPILE_LOG_LEVEL <= DDWAF_COMPILE_LOG_INFO
namespace {
const char *log_level_to_str(DDWAF_LOG_LEVEL level)
{
    switch (level) {
    case DDWAF_LOG_TRACE:
        return "trace";
    case DDWAF_LOG_DEBUG:
        return "debug";
    case DDWAF_LOG_ERROR:
        return "error";
    case DDWAF_LOG_WARN:
        return "warn";
    case DDWAF_LOG_INFO:
        return "info";
    case DDWAF_LOG_OFF:
        break;
    }

    return "off";
}

std::shared_ptr<ddwaf::obfuscator> obfuscator_from_config(const ddwaf_config *config)
{
    std::string_view key_regex;
    std::string_view value_regex;

    if (config != nullptr) {
        if (config->obfuscator.key_regex != nullptr) {
            key_regex = config->obfuscator.key_regex;
        }

        if (config->obfuscator.value_regex != nullptr) {
            value_regex = config->obfuscator.value_regex;
        }
    }

    return std::make_shared<ddwaf::obfuscator>(key_regex, value_regex);
}

ddwaf::object_limits limits_from_config(const ddwaf_config *config)
{
    ddwaf::object_limits limits;

    if (config != nullptr) {
        if (config->limits.max_container_size != 0) {
            limits.max_container_size = config->limits.max_container_size;
        }

        if (config->limits.max_container_depth != 0) {
            limits.max_container_depth = config->limits.max_container_depth;
        }

        if (config->limits.max_string_length != 0) {
            limits.max_string_length = config->limits.max_string_length;
        }
    }

    return limits;
}

} // namespace

#endif
// explicit instantiation declaration to suppress warning
extern "C" {
ddwaf::waf *ddwaf_init(
    const ddwaf_object *ruleset, const ddwaf_config *config, ddwaf_object *diagnostics)
{
    try {
        if (ruleset != nullptr) {
            auto free_fn = config != nullptr ? config->free_fn : ddwaf_object_free;
            ddwaf::waf_builder builder(
                limits_from_config(config), free_fn, obfuscator_from_config(config));

            const ddwaf::parameter input = *ruleset;
            if (diagnostics == nullptr) {
                ddwaf::null_ruleset_info ri;

                auto input_map = static_cast<ddwaf::parameter::map>(input);
                builder.add_or_update("default", input_map, ri);
                return new ddwaf::waf{builder.build()};
            }

            ddwaf::ruleset_info ri;
            const ddwaf::scope_exit on_exit([&]() { ri.to_object(*diagnostics); });
            auto input_map = static_cast<ddwaf::parameter::map>(input);
            builder.add_or_update("default", input_map, ri);
            return new ddwaf::waf{builder.build()};
        }
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return nullptr;
}

void ddwaf_destroy(ddwaf::waf *handle)
{
    if (handle == nullptr) {
        return;
    }

    try {
        delete handle;
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }
}

const char *const *ddwaf_known_addresses(ddwaf::waf *handle, uint32_t *size)
{
    if (handle == nullptr) {
        *size = 0;
        return nullptr;
    }

    const auto &addresses = handle->get_root_addresses();
    if (addresses.empty() || addresses.size() > std::numeric_limits<uint32_t>::max()) {
        *size = 0;
        return nullptr;
    }

    *size = (uint32_t)addresses.size();
    return addresses.data();
}

const char *const *ddwaf_known_actions(ddwaf::waf *handle, uint32_t *size)
{
    if (handle == nullptr) {
        *size = 0;
        return nullptr;
    }

    const auto &action_types = handle->get_available_action_types();
    if (action_types.empty() || action_types.size() > std::numeric_limits<uint32_t>::max()) {
        *size = 0;
        return nullptr;
    }

    *size = (uint32_t)action_types.size();
    return action_types.data();
}

ddwaf_context ddwaf_context_init(ddwaf::waf *handle)
{
    try {
        if (handle != nullptr) {
            return handle->create_context();
        }
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }
    return nullptr;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
DDWAF_RET_CODE ddwaf_run(ddwaf_context context, ddwaf_object *persistent_data,
    ddwaf_object *ephemeral_data, ddwaf_result *result, uint64_t timeout)
{
    if (result != nullptr) {
        *result = DDWAF_RESULT_INITIALISER;
    }

    if (context == nullptr || (persistent_data == nullptr && ephemeral_data == nullptr)) {
        DDWAF_WARN("Illegal WAF call: context or data was null");
        return DDWAF_ERR_INVALID_ARGUMENT;
    }
    try {
        optional_ref<ddwaf_result> res{std::nullopt};
        if (result != nullptr) {
            res = *result;
        }

        optional_ref<ddwaf_object> persistent{std::nullopt};
        if (persistent_data != nullptr) {
            persistent = *persistent_data;
        }

        optional_ref<ddwaf_object> ephemeral{std::nullopt};
        if (ephemeral_data != nullptr) {
            ephemeral = *ephemeral_data;
        }

        // The timers will actually count nanoseconds, std::chrono doesn't
        // deal well with durations being beyond range.
        constexpr uint64_t max_timeout_ms = std::chrono::nanoseconds::max().count() / 1000;
        timeout = std::min(timeout, max_timeout_ms);

        return context->run(persistent, ephemeral, res, timeout);
    } catch (const std::exception &e) {
        // catch-all to avoid std::terminate
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return DDWAF_ERR_INTERNAL;
}

void ddwaf_context_destroy(ddwaf_context context)
{
    if (context == nullptr) {
        return;
    }

    try {
        delete context;
    } catch (const std::exception &e) {
        // catch-all to avoid std::terminate
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }
}

const char *ddwaf_get_version() { return ddwaf::current_version.cstring(); }

bool ddwaf_set_log_cb(ddwaf_log_cb cb, DDWAF_LOG_LEVEL min_level)
{
    ddwaf::logger::init(cb, min_level);
    DDWAF_INFO("Sending log messages to binding, min level {}", log_level_to_str(min_level));
    return true;
}

void ddwaf_result_free(ddwaf_result *result)
{
    // NOLINTNEXTLINE
    ddwaf_object_free(&result->events);
    ddwaf_object_free(&result->actions);
    ddwaf_object_free(&result->derivatives);

    *result = DDWAF_RESULT_INITIALISER;
}

ddwaf_builder ddwaf_builder_init(const ddwaf_config *config)
{
    try {
        auto free_fn = config != nullptr ? config->free_fn : ddwaf_object_free;
        return new ddwaf::waf_builder(
            limits_from_config(config), free_fn, obfuscator_from_config(config));
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return nullptr;
}

bool ddwaf_builder_add_or_update_config(ddwaf::waf_builder *builder, const char *path,
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    uint32_t path_len, ddwaf_object *config, ddwaf_object *diagnostics)
{
    if (builder == nullptr) {
        return false;
    }

    try {
        auto input = static_cast<ddwaf::parameter>(*config);
        auto input_map = static_cast<ddwaf::parameter::map>(input);

        if (diagnostics == nullptr) {
            ddwaf::null_ruleset_info ri;
            return builder->add_or_update({path, path_len}, input_map, ri);
        }

        ddwaf::ruleset_info ri;
        const ddwaf::scope_exit on_exit([&]() { ri.to_object(*diagnostics); });
        return builder->add_or_update({path, path_len}, input_map, ri);
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return false;
}

bool ddwaf_builder_remove_config(ddwaf::waf_builder *builder, const char *path, uint32_t path_len)
{
    if (builder == nullptr) {
        return false;
    }

    try {
        return builder->remove({path, path_len});
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return false;
}

ddwaf_handle ddwaf_builder_build_instance(ddwaf::waf_builder *builder)
{
    if (builder == nullptr) {
        return nullptr;
    }

    try {
        return new ddwaf::waf{builder->build()};
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return nullptr;
}

void ddwaf_builder_destroy(ddwaf_builder builder) { delete builder; }
}
