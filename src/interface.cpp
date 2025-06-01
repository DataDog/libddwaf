// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include "builder/waf_builder.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "context.hpp"
#include "ddwaf.h"
#include "log.hpp"
#include "obfuscator.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "re2.h"
#include "ruleset_info.hpp"
#include "utils.hpp"
#include "version.hpp"
#include "waf.hpp"

using namespace ddwaf;

// Object compatibility

// detail::object == ddwaf_object
static_assert(sizeof(detail::object) == sizeof(ddwaf_object));
static_assert(offsetof(detail::object, type) == offsetof(ddwaf_object, type));
static_assert(offsetof(detail::object, via) == offsetof(ddwaf_object, via));

// detail::object_kv == _ddwaf_object_kv
static_assert(sizeof(detail::object_kv) == sizeof(struct _ddwaf_object_kv));
static_assert(offsetof(detail::object_kv, key) == offsetof(_ddwaf_object_kv, key));
static_assert(offsetof(detail::object_kv, val) == offsetof(_ddwaf_object_kv, val));

// detail::object_scalar<bool> == _ddwaf_object_bool
static_assert(sizeof(detail::object_scalar<bool>) == sizeof(_ddwaf_object_bool));
static_assert(offsetof(detail::object_scalar<bool>, type) == offsetof(_ddwaf_object_bool, type));
static_assert(offsetof(detail::object_scalar<bool>, val) == offsetof(_ddwaf_object_bool, val));

// detail::object_scalar<int64_t> == _ddwaf_object_signed
static_assert(sizeof(detail::object_scalar<int64_t>) == sizeof(_ddwaf_object_signed));
static_assert(
    offsetof(detail::object_scalar<int64_t>, type) == offsetof(_ddwaf_object_signed, type));
static_assert(offsetof(detail::object_scalar<int64_t>, val) == offsetof(_ddwaf_object_signed, val));

// detail::object_scalar<uint64_t> == _ddwaf_object_unsigned
static_assert(sizeof(detail::object_scalar<uint64_t>) == sizeof(_ddwaf_object_unsigned));
static_assert(
    offsetof(detail::object_scalar<uint64_t>, type) == offsetof(_ddwaf_object_unsigned, type));
static_assert(
    offsetof(detail::object_scalar<uint64_t>, val) == offsetof(_ddwaf_object_unsigned, val));

// detail::object_scalar<double> == _ddwaf_object_float
static_assert(sizeof(detail::object_scalar<double>) == sizeof(_ddwaf_object_float));
static_assert(offsetof(detail::object_scalar<double>, type) == offsetof(_ddwaf_object_float, type));
static_assert(offsetof(detail::object_scalar<double>, val) == offsetof(_ddwaf_object_float, val));

// detail::object_string == _ddwaf_object_string
static_assert(sizeof(detail::object_string) == sizeof(_ddwaf_object_string));
static_assert(offsetof(detail::object_string, type) == offsetof(_ddwaf_object_string, type));
static_assert(offsetof(detail::object_string, size) == offsetof(_ddwaf_object_string, size));
static_assert(offsetof(detail::object_string, ptr) == offsetof(_ddwaf_object_string, ptr));

// detail::object_small_string == _ddwaf_object_small_string
static_assert(sizeof(detail::object_small_string) == sizeof(_ddwaf_object_small_string));
static_assert(
    offsetof(detail::object_small_string, type) == offsetof(_ddwaf_object_small_string, type));
static_assert(
    offsetof(detail::object_small_string, size) == offsetof(_ddwaf_object_small_string, size));
static_assert(
    offsetof(detail::object_small_string, data) == offsetof(_ddwaf_object_small_string, data));

// detail::object_array == _ddwaf_object_array
static_assert(sizeof(detail::object_array) == sizeof(_ddwaf_object_array));
static_assert(offsetof(detail::object_array, type) == offsetof(_ddwaf_object_array, type));
static_assert(offsetof(detail::object_array, size) == offsetof(_ddwaf_object_array, size));
static_assert(offsetof(detail::object_array, capacity) == offsetof(_ddwaf_object_array, capacity));
static_assert(offsetof(detail::object_array, ptr) == offsetof(_ddwaf_object_array, ptr));

// detail::object_map == _ddwaf_object_map
static_assert(sizeof(detail::object_map) == sizeof(_ddwaf_object_map));
static_assert(offsetof(detail::object_map, type) == offsetof(_ddwaf_object_map, type));
static_assert(offsetof(detail::object_map, size) == offsetof(_ddwaf_object_map, size));
static_assert(offsetof(detail::object_map, capacity) == offsetof(_ddwaf_object_map, capacity));
static_assert(offsetof(detail::object_map, ptr) == offsetof(_ddwaf_object_map, ptr));

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

std::shared_ptr<ddwaf::match_obfuscator> obfuscator_from_config(const ddwaf_config *config)
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

    return std::make_shared<ddwaf::match_obfuscator>(key_regex, value_regex);
}

// Maximum number of characters required to represent a 64 bit integer as a string
// 20 bytes for UINT64_MAX or INT64_MIN + null byte
constexpr size_t UINT64_CHARS = 21;
// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
detail::object *to_ptr(ddwaf_object *ptr) { return reinterpret_cast<detail::object *>(ptr); }
const detail::object *to_ptr(const ddwaf_object *ptr)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const detail::object *>(ptr);
}

detail::object &to_ref(ddwaf_object *ptr) { return *to_ptr(ptr); }
const detail::object &to_ref(const ddwaf_object *ptr) { return *to_ptr(ptr); }

borrowed_object to_borrowed(ddwaf_object *ptr)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return borrowed_object{reinterpret_cast<detail::object *>(ptr)};
}
} // namespace

// explicit instantiation declaration to suppress warning
extern "C" {
ddwaf::waf *ddwaf_init(
    const ddwaf_object *ruleset, const ddwaf_config *config, ddwaf_object *diagnostics)
{
    try {
        if (ruleset != nullptr) {
            auto free_fn = config != nullptr ? config->free_fn : ddwaf_object_free;
            ddwaf::waf_builder builder(free_fn, obfuscator_from_config(config));

            ddwaf::raw_configuration input{to_ref(ruleset)};
            if (diagnostics == nullptr) {
                ddwaf::null_ruleset_info ri;

                builder.add_or_update("default", input, ri);
                return new ddwaf::waf{builder.build()};
            }

            ddwaf::ruleset_info ri;
            const ddwaf::scope_exit on_exit([&]() { to_ref(diagnostics) = ri.to_object().move(); });
            builder.add_or_update("default", input, ri);
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

DDWAF_RET_CODE ddwaf_run(ddwaf_context context, ddwaf_object *persistent_data,
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    ddwaf_object *ephemeral_data, ddwaf_object *result, uint64_t timeout)
{
    if (context == nullptr || (persistent_data == nullptr && ephemeral_data == nullptr)) {
        DDWAF_WARN("Illegal WAF call: context or data was null");
        return DDWAF_ERR_INVALID_ARGUMENT;
    }

    try {
        auto free_fn = context->get_free_fn();

        if (persistent_data != nullptr &&
            !context->insert(
                owned_object{// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    to_ref(persistent_data), reinterpret_cast<detail::object_free_fn>(free_fn)})) {
            return DDWAF_ERR_INVALID_OBJECT;
        }

        if (ephemeral_data != nullptr &&
            !context->insert(owned_object{to_ref(ephemeral_data),
                                 // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                                 reinterpret_cast<detail::object_free_fn>(free_fn)},
                context::attribute::ephemeral)) {
            return DDWAF_ERR_INVALID_OBJECT;
        }

        // The timers will actually count nanoseconds, std::chrono doesn't
        // deal well with durations being beyond range.
        constexpr uint64_t max_timeout_ms = std::chrono::nanoseconds::max().count() / 1000;
        timeout = std::min(timeout, max_timeout_ms);

        auto [code, res] = context->run(timeout);
        if (result != nullptr) {
            to_ref(result) = res.move();
        }
        return code ? DDWAF_MATCH : DDWAF_OK;
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

ddwaf_builder ddwaf_builder_init(const ddwaf_config *config)
{
    try {
        auto free_fn = config != nullptr ? config->free_fn : ddwaf_object_free;
        return new ddwaf::waf_builder(free_fn, obfuscator_from_config(config));
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return nullptr;
}

bool ddwaf_builder_add_or_update_config(ddwaf::waf_builder *builder, const char *path,
    uint32_t path_len, const ddwaf_object *config, ddwaf_object *diagnostics)
{
    if (builder == nullptr || path == nullptr || path_len == 0 || config == nullptr) {
        return false;
    }

    try {
        auto input = static_cast<ddwaf::raw_configuration>(to_ref(config));

        if (diagnostics == nullptr) {
            ddwaf::null_ruleset_info ri;
            return builder->add_or_update({path, path_len}, input, ri);
        }

        ddwaf::ruleset_info ri;
        const ddwaf::scope_exit on_exit([&]() { to_ref(diagnostics) = ri.to_object().move(); });
        return builder->add_or_update({path, path_len}, input, ri);
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return false;
}

bool ddwaf_builder_remove_config(ddwaf::waf_builder *builder, const char *path, uint32_t path_len)
{
    if (builder == nullptr || path == nullptr || path_len == 0) {
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

uint32_t ddwaf_builder_get_config_paths(
    ddwaf_builder builder, ddwaf_object *paths, const char *filter, uint32_t filter_len)
{
    if (builder == nullptr) {
        return 0;
    }

    try {
        std::vector<std::string_view> config_paths;
        if (filter != nullptr) {
            re2::RE2::Options options;
            options.set_log_errors(false);
            options.set_case_sensitive(true);

            re2::RE2 regex_filter{{filter, static_cast<std::size_t>(filter_len)}, options};
            config_paths = builder->get_filtered_config_paths(regex_filter);
        } else {
            config_paths = builder->get_config_paths();
        }

        if (paths != nullptr) {
            ddwaf_object_array(paths);
            // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
            for (const auto &value : config_paths) {
                ddwaf_object tmp{};
                ddwaf_object_array_add(
                    paths, ddwaf_object_stringl(&tmp, value.data(), value.size()));
            }
        }
        return config_paths.size();
    } catch (const std::exception &e) {
        DDWAF_ERROR("{}", e.what());
    } catch (...) {
        DDWAF_ERROR("unknown exception");
    }

    return 0;
}

void ddwaf_builder_destroy(ddwaf_builder builder) { delete builder; }

ddwaf_object *ddwaf_object_invalid(ddwaf_object *object)
{
    if (object == nullptr) {
        return nullptr;
    }

    to_ref(object) = owned_object{}.move();

    return object;
}

ddwaf_object *ddwaf_object_null(ddwaf_object *object)
{
    if (object == nullptr) {
        return nullptr;
    }

    to_ref(object) = owned_object{nullptr}.move();

    return object;
}

ddwaf_object *ddwaf_object_string(ddwaf_object *object, const char *string)
{
    if (object == nullptr || string == nullptr) {
        return nullptr;
    }
    to_ref(object) = owned_object{string}.move();
    return object;
}

ddwaf_object *ddwaf_object_stringl(ddwaf_object *object, const char *string, size_t length)
{
    if (object == nullptr || string == nullptr) {
        return nullptr;
    }

    to_ref(object) = owned_object{string, length}.move();
    return object;
}

ddwaf_object *ddwaf_object_stringl_nc(ddwaf_object *object, const char *string, size_t length)
{
    if (object == nullptr || string == nullptr) {
        return nullptr;
    }

    to_ref(object) = owned_object::make_string_nocopy(string, length).move();
    return object;
}

// TODO: deprecate
ddwaf_object *ddwaf_object_string_from_signed(ddwaf_object *object, int64_t value)
{
    if (object == nullptr) {
        return nullptr;
    }

    // INT64_MIN is 20 char long
    char container[UINT64_CHARS] = {0};
    const auto length = static_cast<std::size_t>(
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        snprintf(container, sizeof(container), "%" PRId64, value));

    return ddwaf_object_stringl(object, container, length);
}

// TODO: deprecate
ddwaf_object *ddwaf_object_string_from_unsigned(ddwaf_object *object, uint64_t value)
{
    if (object == nullptr) {
        return nullptr;
    }

    // UINT64_MAX is 20 char long
    char container[UINT64_CHARS] = {0};

    const auto length = static_cast<size_t>(
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        snprintf(container, sizeof(container), "%" PRIu64, value));

    return ddwaf_object_stringl(object, container, length);
}

ddwaf_object *ddwaf_object_unsigned(ddwaf_object *object, uint64_t value)
{
    if (object == nullptr) {
        return nullptr;
    }

    to_ref(object) = owned_object{value}.move();
    return object;
}

ddwaf_object *ddwaf_object_signed(ddwaf_object *object, int64_t value)
{
    if (object == nullptr) {
        return nullptr;
    }

    to_ref(object) = owned_object{value}.move();
    return object;
}

ddwaf_object *ddwaf_object_bool(ddwaf_object *object, bool value)
{
    if (object == nullptr) {
        return nullptr;
    }
    to_ref(object) = owned_object{value}.move();
    return object;
}

ddwaf_object *ddwaf_object_float(ddwaf_object *object, double value)
{
    if (object == nullptr) {
        return nullptr;
    }
    to_ref(object) = owned_object{value}.move();
    return object;
}

ddwaf_object *ddwaf_object_array(ddwaf_object *object)
{
    if (object == nullptr) {
        return nullptr;
    }
    to_ref(object) = owned_object::make_array().move();
    return object;
}

ddwaf_object *ddwaf_object_map(ddwaf_object *object)
{
    if (object == nullptr) {
        return nullptr;
    }

    to_ref(object) = owned_object::make_map().move();
    return object;
}

bool ddwaf_object_array_add(ddwaf_object *array, ddwaf_object *object)
{
    if (array == nullptr || array->type != DDWAF_OBJ_ARRAY || object == nullptr) {
        return false;
    }

    try {
        to_borrowed(array).emplace_back(owned_object{to_ref(object)});
        return true;
    } catch (...) {} // NOLINT(bugprone-empty-catch)
    return false;
}

bool ddwaf_object_map_add(ddwaf_object *map, const char *key, ddwaf_object *object)
{
    if (map == nullptr || map->type != DDWAF_OBJ_MAP || key == nullptr || object == nullptr) {
        return false;
    }

    try {
        to_borrowed(map).emplace(std::string_view{key}, owned_object{to_ref(object)});
        return true;
    } catch (...) {} // NOLINT(bugprone-empty-catch)
    return false;
}

bool ddwaf_object_map_addl(ddwaf_object *map, const char *key, size_t length, ddwaf_object *object)
{
    if (map == nullptr || map->type != DDWAF_OBJ_MAP || key == nullptr || object == nullptr) {
        return false;
    }

    try {
        to_borrowed(map).emplace(std::string_view{key, length}, owned_object{to_ref(object)});
        return true;
    } catch (...) {} // NOLINT(bugprone-empty-catch)
    return false;
}

bool ddwaf_object_map_addl_nc(
    ddwaf_object *map, const char *key, size_t length, ddwaf_object *object)
{
    if (map == nullptr || map->type != DDWAF_OBJ_MAP || key == nullptr || object == nullptr) {
        return false;
    }

    try {
        to_borrowed(map).emplace(
            owned_object::make_string_nocopy(key, length), owned_object{to_ref(object)});
        return true;
    } catch (...) {} // NOLINT(bugprone-empty-catch)
    return false;
}

// NOLINTNEXTLINE(misc-no-recursion)
void ddwaf_object_free(ddwaf_object *object)
{
    if (object == nullptr) {
        return;
    }

    detail::object_destroy(to_ref(object));

    ddwaf_object_invalid(object);
}

DDWAF_OBJ_TYPE ddwaf_object_type(const ddwaf_object *object)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value()) {
        return DDWAF_OBJ_INVALID;
    }

    return static_cast<DDWAF_OBJ_TYPE>(view.type());
}

size_t ddwaf_object_size(const ddwaf_object *object)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is_container()) {
        return 0;
    }

    return view.size();
}

size_t ddwaf_object_length(const ddwaf_object *object)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is_string()) {
        return 0;
    }

    return view.size();
}

const char *ddwaf_object_get_string(const ddwaf_object *object, size_t *length)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is_string()) {
        return nullptr;
    }

    if (length != nullptr) {
        *length = view.size();
    }

    return view.data();
}

uint64_t ddwaf_object_get_unsigned(const ddwaf_object *object)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is<uint64_t>()) {
        return 0;
    }
    return view.as<uint64_t>();
}

int64_t ddwaf_object_get_signed(const ddwaf_object *object)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is<int64_t>()) {
        return 0;
    }
    return view.as<int64_t>();
}

double ddwaf_object_get_float(const ddwaf_object *object)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is<double>()) {
        return 0;
    }
    return view.as<double>();
}

bool ddwaf_object_get_bool(const ddwaf_object *object)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is<bool>()) {
        return false;
    }
    return view.as<bool>();
}

const ddwaf_object *ddwaf_object_at_key(const ddwaf_object *object, size_t index)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is_map() || index >= view.size()) {
        return nullptr;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const ddwaf_object *>(view.at_key(index).ptr());
}

const ddwaf_object *ddwaf_object_at_value(const ddwaf_object *object, size_t index)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is_container() || index >= view.size()) {
        return nullptr;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const ddwaf_object *>(view.at_value(index).ptr());
}

const ddwaf_object *ddwaf_object_find(const ddwaf_object *object, const char *key, size_t length)
{
    const object_view view{to_ptr(object)};
    if (!view.has_value() || !view.is_map() || view.empty() || key == nullptr || length == 0) {
        return nullptr;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const ddwaf_object *>(view.find(std::string_view{key, length}).ptr());
}
}
