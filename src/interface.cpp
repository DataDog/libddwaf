// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <context.hpp>
#include <context_allocator.hpp>
#include <exception.hpp>
#include <memory>
#include <mutex>
#include <obfuscator.hpp>
#include <ruleset_info.hpp>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utils.hpp>
#include <waf.hpp>

#include <log.hpp>

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
            ddwaf::parameter input = *ruleset;

            auto free_fn = config != nullptr ? config->free_fn : ddwaf_object_free;
            if (diagnostics == nullptr) {
                ddwaf::null_ruleset_info ri;
                return new ddwaf::waf(
                    input, ri, limits_from_config(config), free_fn, obfuscator_from_config(config));
            }

            ddwaf::ruleset_info ri;
            ddwaf::scope_exit on_exit([&]() { ri.to_object(*diagnostics); });

            return new ddwaf::waf(
                input, ri, limits_from_config(config), free_fn, obfuscator_from_config(config));
        }
    } catch (const std::exception &e) {
        DDWAF_ERROR("%s", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return nullptr;
}

ddwaf::waf *ddwaf_update(ddwaf::waf *handle, const ddwaf_object *ruleset, ddwaf_object *diagnostics)
{
    try {
        if (handle != nullptr && ruleset != nullptr) {
            ddwaf::parameter input = *ruleset;
            if (diagnostics == nullptr) {
                ddwaf::null_ruleset_info ri;
                return handle->update(input, ri);
            }

            ddwaf::ruleset_info ri;
            ddwaf::scope_exit on_exit([&]() { ri.to_object(*diagnostics); });

            return handle->update(input, ri);
        }
    } catch (const std::exception &e) {
        DDWAF_ERROR("%s", e.what());
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
        DDWAF_ERROR("%s", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }
}

const char *const *ddwaf_required_addresses(ddwaf::waf *handle, uint32_t *size)
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

ddwaf_context ddwaf_context_init(ddwaf::waf *handle)
{
    try {
        if (handle != nullptr) {
            return handle->create_context();
        }
    } catch (const std::exception &e) {
        DDWAF_ERROR("%s", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }
    return nullptr;
}

DDWAF_RET_CODE ddwaf_run(
    ddwaf_context context, ddwaf_object *data, ddwaf_result *result, uint64_t timeout)
{
    if (result != nullptr) {
        *result = DDWAF_RESULT_INITIALISER;
    }

    if (context == nullptr || data == nullptr) {
        DDWAF_WARN("Illegal WAF call: context or data was null");
        return DDWAF_ERR_INVALID_ARGUMENT;
    }
    try {
        optional_ref<ddwaf_result> res{std::nullopt};
        if (result != nullptr) {
            res = *result;
        }

        return context->run(*data, res, timeout);
    } catch (const std::exception &e) {
        // catch-all to avoid std::terminate
        DDWAF_ERROR("%s", e.what());
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
        DDWAF_ERROR("%s", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }
}

const char *ddwaf_get_version() { return LIBDDWAF_VERSION; }

bool ddwaf_set_log_cb(ddwaf_log_cb cb, DDWAF_LOG_LEVEL min_level)
{
    ddwaf::logger::init(cb, min_level);
    DDWAF_INFO("Sending log messages to binding, min level %s", log_level_to_str(min_level));
    return true;
}

void ddwaf_result_free(ddwaf_result *result)
{
    // NOLINTNEXTLINE
    ddwaf_object_free(&result->events);

    ddwaf_object_free(&result->actions);

    *result = DDWAF_RESULT_INITIALISER;
}
}
