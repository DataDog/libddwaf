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
#include <optional>
#include <string_view>
#include <vector>

#include "builder/waf_builder.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "context.hpp"
#include "ddwaf.h"
#include "log.hpp"
#include "obfuscator.hpp"
#include "re2.h"
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

// Maximum number of characters required to represent a 64 bit integer as a string
// 20 bytes for UINT64_MAX or INT64_MIN + null byte
constexpr size_t UINT64_CHARS = 21;

inline bool is_container(const ddwaf_object *obj)
{
    return (obj->type & PWI_CONTAINER_TYPES) != 0 && obj->array != nullptr;
}

ddwaf_object *ddwaf_object_string_helper(ddwaf_object *object, const char *string, size_t length)
{
    if (length == SIZE_MAX) {
        DDWAF_DEBUG("invalid string length: {}", length);
        return nullptr;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,hicpp-no-malloc)
    char *copy = reinterpret_cast<char *>(malloc(length + 1));
    if (copy == nullptr) {
        return nullptr;
    }

    memcpy(copy, string, length);
    copy[length] = '\0';

    *object = {nullptr, 0, {copy}, length, DDWAF_OBJ_STRING};

    return object;
}

bool ddwaf_object_insert(ddwaf_object *array, ddwaf_object object)
{
    // We preallocate 8 entries
    if (array->nbEntries == 0) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,hicpp-no-malloc)
        array->array = reinterpret_cast<ddwaf_object *>(malloc(8 * sizeof(ddwaf_object)));
        if (array->array == nullptr) {
            DDWAF_DEBUG("Allocation failure when trying to initialize a map or an array");
            return false;
        }
    }
    // If we're exceeding our preallocation, add 8 more
    else if ((array->nbEntries & 0x7) == 0) {
        if (array->nbEntries + 8 > SIZE_MAX / sizeof(ddwaf_object)) {
            return false;
        }

        const auto size = (size_t)(array->nbEntries + 8);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto *newArray = reinterpret_cast<ddwaf_object *>(
            // NOLINTNEXTLINE(hicpp-no-malloc)
            realloc((void *)array->array, size * sizeof(ddwaf_object)));
        if (newArray == nullptr) {
            DDWAF_DEBUG("Allocation failure when trying to lengthen a map or an array");
            return false;
        }
        array->array = newArray;
    }

    memcpy(&(array->array)[array->nbEntries], &object, sizeof(ddwaf_object));
    array->nbEntries += 1;
    return true;
}

inline bool ddwaf_object_map_add_valid(ddwaf_object *map, const char *key, ddwaf_object *object)
{
    if (map == nullptr || map->type != DDWAF_OBJ_MAP || key == nullptr) {
        DDWAF_DEBUG("Invalid call, this API can only be called with a map as first parameter");
        return false;
    }
    if (key == nullptr) {
        DDWAF_DEBUG("Invalid call, nullptr key");
        return false;
    }
    if (object == nullptr) {
        DDWAF_DEBUG("Tried to add a null object to a map");
        return false;
    }
    return true;
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
            ddwaf::waf_builder builder(free_fn, obfuscator_from_config(config));

            ddwaf::raw_configuration input = *ruleset;
            if (diagnostics == nullptr) {
                ddwaf::null_ruleset_info ri;

                builder.add_or_update("default", input, ri);
                return new ddwaf::waf{builder.build()};
            }

            ddwaf::ruleset_info ri;
            const ddwaf::scope_exit on_exit([&]() { *diagnostics = ri.to_object().move(); });
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
        auto input = static_cast<ddwaf::raw_configuration>(*config);

        if (diagnostics == nullptr) {
            ddwaf::null_ruleset_info ri;
            return builder->add_or_update({path, path_len}, input, ri);
        }

        ddwaf::ruleset_info ri;
        const ddwaf::scope_exit on_exit([&]() { *diagnostics = ri.to_object().move(); });
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
            for (const auto &value : config_paths) {
                ddwaf_object tmp;
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

    *object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_INVALID};

    return object;
}

ddwaf_object *ddwaf_object_null(ddwaf_object *object)
{
    if (object == nullptr) {
        return nullptr;
    }

    *object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_NULL};

    return object;
}

ddwaf_object *ddwaf_object_string(ddwaf_object *object, const char *string)
{
    if (object == nullptr) {
        return nullptr;
    }

    if (string == nullptr) {
        DDWAF_DEBUG("tried to create a string from a nullptr pointer");
        return nullptr;
    }
    return ddwaf_object_string_helper(object, string, strlen(string));
}

ddwaf_object *ddwaf_object_stringl(ddwaf_object *object, const char *string, size_t length)
{
    if (object == nullptr) {
        return nullptr;
    }

    if (string == nullptr) {
        DDWAF_DEBUG("Tried to create a string from a nullptr pointer");
        return nullptr;
    }

    return ddwaf_object_string_helper(object, string, length);
}

ddwaf_object *ddwaf_object_stringl_nc(ddwaf_object *object, const char *string, size_t length)
{
    if (object == nullptr) {
        return nullptr;
    }

    if (string == nullptr) {
        DDWAF_DEBUG("Tried to create a string from an nullptr pointer");
        return nullptr;
    }

    *object = {nullptr, 0, {string}, length, DDWAF_OBJ_STRING};

    return object;
}

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

    *object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_UNSIGNED};
    object->uintValue = value;

    return object;
}

ddwaf_object *ddwaf_object_signed(ddwaf_object *object, int64_t value)
{
    if (object == nullptr) {
        return nullptr;
    }

    *object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_SIGNED};
    object->intValue = value;

    return object;
}

ddwaf_object *ddwaf_object_bool(ddwaf_object *object, bool value)
{
    if (object == nullptr) {
        return nullptr;
    }

    *object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_BOOL};
    object->boolean = value;

    return object;
}

ddwaf_object *ddwaf_object_float(ddwaf_object *object, double value)
{
    if (object == nullptr) {
        return nullptr;
    }

    *object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_FLOAT};
    object->f64 = value;

    return object;
}

ddwaf_object *ddwaf_object_array(ddwaf_object *object)
{
    if (object == nullptr) {
        return nullptr;
    }

    *object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_ARRAY};

    return object;
}

ddwaf_object *ddwaf_object_map(ddwaf_object *object)
{
    if (object == nullptr) {
        return nullptr;
    }

    *object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_MAP};

    return object;
}

bool ddwaf_object_array_add(ddwaf_object *array, ddwaf_object *object)
{
    if (array == nullptr || array->type != DDWAF_OBJ_ARRAY) {
        DDWAF_DEBUG("Invalid call, this API can only be called with an array as first parameter");
        return false;
    }
    if (object == nullptr) {
        DDWAF_DEBUG("Tried to add a null object to an array");
        return false;
    }
    return ddwaf_object_insert(array, *object);
}

bool ddwaf_object_map_add_helper(
    ddwaf_object *map, const char *key, size_t length, ddwaf_object object)
{
    if (length == SIZE_MAX) {
        DDWAF_DEBUG("invalid key length: {}", length);
        return false;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,hicpp-no-malloc)
    char *name = reinterpret_cast<char *>(malloc((length + 1) * sizeof(char)));
    if (name == nullptr) {
        DDWAF_DEBUG("Allocation failure when trying to allocate the map key");
        return false;
    }

    memcpy(name, key, length);
    name[length] = '\0';

    object.parameterName = name;
    object.parameterNameLength = length;

    if (!ddwaf_object_insert(map, object)) {

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast,hicpp-no-malloc)
        free((void *)object.parameterName);
        return false;
    }
    return true;
}

bool ddwaf_object_map_add(ddwaf_object *map, const char *key, ddwaf_object *object)
{
    if (!ddwaf_object_map_add_valid(map, key, object)) {
        return false;
    }
    return ddwaf_object_map_add_helper(map, key, strlen(key), *object);
}

bool ddwaf_object_map_addl(ddwaf_object *map, const char *key, size_t length, ddwaf_object *object)
{
    if (!ddwaf_object_map_add_valid(map, key, object)) {
        return false;
    }
    return ddwaf_object_map_add_helper(map, key, length, *object);
}

bool ddwaf_object_map_addl_nc(
    ddwaf_object *map, const char *key, size_t length, ddwaf_object *object)
{
    if (!ddwaf_object_map_add_valid(map, key, object)) {
        return false;
    }

    object->parameterName = key;
    object->parameterNameLength = length;

    return ddwaf_object_insert(map, *object);
}

// NOLINTNEXTLINE(misc-no-recursion)
void ddwaf_object_free(ddwaf_object *object)
{
    if (object == nullptr) {
        return;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast,hicpp-no-malloc)
    free((void *)object->parameterName);

    switch (object->type) {
    case DDWAF_OBJ_MAP:
    case DDWAF_OBJ_ARRAY: {
        auto *value = object->array;
        if (value != nullptr) {
            for (uint64_t i = 0; i < object->nbEntries; ++i) { ddwaf_object_free(&value[i]); }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast,hicpp-no-malloc)
            free(value);
        }
        break;
    }
    case DDWAF_OBJ_STRING:
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast,hicpp-no-malloc)
        free((void *)object->stringValue);
        break;
    default:
        break;
    }

    ddwaf_object_invalid(object);
}

DDWAF_OBJ_TYPE ddwaf_object_type(const ddwaf_object *object)
{
    return object != nullptr ? object->type : DDWAF_OBJ_INVALID;
}

size_t ddwaf_object_size(const ddwaf_object *object)
{
    if (object == nullptr || !is_container(object)) {
        return 0;
    }

    return object->nbEntries;
}

size_t ddwaf_object_length(const ddwaf_object *object)
{
    if (object == nullptr || object->type != DDWAF_OBJ_STRING) {
        return 0;
    }

    return object->nbEntries;
}

const char *ddwaf_object_get_key(const ddwaf_object *object, size_t *length)
{
    if (object == nullptr || object->parameterName == nullptr) {
        return nullptr;
    }

    if (length != nullptr) {
        *length = object->parameterNameLength;
    }

    return object->parameterName;
}

const char *ddwaf_object_get_string(const ddwaf_object *object, size_t *length)
{
    if (object == nullptr || object->type != DDWAF_OBJ_STRING) {
        return nullptr;
    }

    if (length != nullptr) {
        *length = object->nbEntries;
    }

    return object->stringValue;
}

uint64_t ddwaf_object_get_unsigned(const ddwaf_object *object)
{
    if (object == nullptr || object->type != DDWAF_OBJ_UNSIGNED) {
        return 0;
    }

    return object->uintValue;
}

int64_t ddwaf_object_get_signed(const ddwaf_object *object)
{
    if (object == nullptr || object->type != DDWAF_OBJ_SIGNED) {
        return 0;
    }

    return object->intValue;
}

double ddwaf_object_get_float(const ddwaf_object *object)
{
    if (object == nullptr || object->type != DDWAF_OBJ_FLOAT) {
        return 0;
    }

    return object->f64;
}

bool ddwaf_object_get_bool(const ddwaf_object *object)
{
    if (object == nullptr || object->type != DDWAF_OBJ_BOOL) {
        return false;
    }

    return object->boolean;
}

const ddwaf_object *ddwaf_object_get_index(const ddwaf_object *object, size_t index)
{
    if (object == nullptr || !is_container(object) || index >= object->nbEntries) {
        return nullptr;
    }

    return &object->array[index];
}
}
