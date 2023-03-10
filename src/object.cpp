// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <log.hpp>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <utils.hpp>

namespace {
// Maximum number of characters required to represent a 64 bit integer as a string
// 20 bytes for UINT64_MAX or INT64_MIN + null byte
constexpr size_t UINT64_CHARS = 21;

class parsing_error : public std::exception
{
public:
    parsing_error(const std::string& what) : what_(what) {}
    const char* what() const noexcept final { return what_.c_str(); }

protected:
    const std::string what_;
};

ddwaf_object ddwaf_object_from_json_rec(const rapidjson::GenericValue<rapidjson::UTF8<>>& json)
{
    ddwaf_object object {};
    json.GetType();
    switch (json.GetType())
    {
        case rapidjson::kObjectType:
        {
            ddwaf_object_map(&object);
            for (const auto& kvp : json.GetObject())
            {
                auto value = ddwaf_object_from_json_rec(kvp.value);
                ddwaf_object_map_add(&object, kvp.name.GetString(), &value);
            }

            return object;
        }
        case rapidjson::kArrayType:
        {
            ddwaf_object_array(&object);
            for (const auto& elem : json.GetArray())
            {
                auto value = ddwaf_object_from_json_rec(elem);
                ddwaf_object_array_add(&object, &value);
            }
            return object;
        }
        case rapidjson::kStringType:
        {
            ddwaf_object_string(&object, json.GetString());
            return object;
        }
        case rapidjson::kNumberType:
        {
            if (json.IsUint64() || json.IsUint())
            {
                ddwaf_object_unsigned(&object, json.GetUint64());
            }
            else if (json.IsInt64() || json.IsInt())
            {
                ddwaf_object_signed(&object, json.GetInt64());
            }
            return object;
        }
        case rapidjson::kTrueType: /* fallthrough */
        case rapidjson::kFalseType:
        {
            ddwaf_object_bool(&object, json.GetBool());
            return object;
        }
        case rapidjson::kNullType: /* fallthrough */
        default:
            throw parsing_error { "Invalid null value in input json" };
    }
}

rapidjson::GenericValue<rapidjson::UTF8<>> ddwaf_object_to_json_rec(
    const ddwaf_object* object, rapidjson::Document::AllocatorType& allocator)
{
    rapidjson::GenericValue<rapidjson::UTF8<>> value {};
    switch (object->type)
    {
        case DDWAF_OBJ_MAP:
        {
            value.SetObject();
            for (decltype(object->nbEntries) i = 0; i < object->nbEntries; i++)
            {
                value.AddMember(rapidjson::Value { object->array[i].parameterName, allocator },
                                ddwaf_object_to_json_rec(object->array + i, allocator).Move(), allocator);
            }
            return value;
        }
        case DDWAF_OBJ_ARRAY:
        {
            value.SetArray();
            for (decltype(object->nbEntries) i = 0; i < object->nbEntries; i++)
            {
                value.PushBack(
                    ddwaf_object_to_json_rec(object->array + i, allocator).Move(), allocator);
            }
            return value;
        }
        case DDWAF_OBJ_BOOL:
        {
            if (strncmp(object->stringValue, "true", 5))
            {
                return rapidjson::Value { true };
            }
            if (strncmp(object->stringValue, "false", 6))
            {
                return rapidjson::Value { false };
            }

            throw parsing_error { "Bad conversion to boolean" };
        }
        case DDWAF_OBJ_STRING:
            return rapidjson::Value { object->stringValue, allocator };
        case DDWAF_OBJ_SIGNED:
            return rapidjson::Value { object->intValue };
        case DDWAF_OBJ_UNSIGNED:
            return rapidjson::Value { object->uintValue };
        case DDWAF_OBJ_INVALID: /* fallthrough */
        default:
            throw parsing_error { "Invalid ddwaf object type" };
    }
}

} // namespace

extern "C"
{
    
ddwaf_object* ddwaf_object_from_json(ddwaf_object* object, const char* json)
{
    rapidjson::Document document {};
    document.Parse(json);
    if (document.HasParseError() || object == nullptr)
    {
        return nullptr;
    }

    try
    {
        *object = ddwaf_object_from_json_rec(document);
    }
    catch (const parsing_error&)
    {
        return nullptr;
    }

    return object;
}

const char* ddwaf_object_to_json(const ddwaf_object* object)
{
    if (object == nullptr)
    {
        return nullptr;
    }

    rapidjson::GenericValue<rapidjson::UTF8<>> root {};
    rapidjson::Document document {};

    try
    {
        root = ddwaf_object_to_json_rec(object, document.GetAllocator());
    }
    catch (const parsing_error&)
    {
        return nullptr;
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer { buffer };
    root.Accept(writer);

    char* malloc_str = (char*) malloc(buffer.GetSize() + 1);
    if (malloc_str == nullptr)
    {
        return nullptr;
    }

    strncpy(malloc_str, buffer.GetString(), buffer.GetSize() + 1);
    return malloc_str;
}

ddwaf_object* ddwaf_object_invalid(ddwaf_object* object)
{
    if (object == NULL)
    {
        return NULL;
    }

    *object = { NULL, 0, { NULL }, 0, DDWAF_OBJ_INVALID };

    return object;
}

static ddwaf_object *ddwaf_object_string_helper(
    ddwaf_object *object, const char *string, size_t length)
{
    if (length == SIZE_MAX) {
        DDWAF_DEBUG("invalid string length: %zu", length);
        return nullptr;
    }

    char *copy = (char *)malloc(length + 1);
    if (copy == nullptr) {
        return nullptr;
    }

    memcpy(copy, string, length);
    copy[length] = '\0';

    *object = {nullptr, 0, {copy}, length, DDWAF_OBJ_STRING};

    return object;
}

ddwaf_object *ddwaf_object_string(ddwaf_object *object, const char *string)
{
    if (object == nullptr) {
        return nullptr;
    }

    if (string == nullptr) {
        DDWAF_DEBUG("tried to create a string from an nullptr pointer");
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
        DDWAF_DEBUG("Tried to create a string from an nullptr pointer");
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

ddwaf_object *ddwaf_object_signed(ddwaf_object *object, int64_t value)
{
    if (object == nullptr) {
        return nullptr;
    }

    // INT64_MIN is 20 char long
    char container[UINT64_CHARS] = {0};
    size_t length = (size_t)snprintf(container, sizeof(container), "%" PRId64, value);

    return ddwaf_object_stringl(object, container, length);
}

ddwaf_object *ddwaf_object_unsigned(ddwaf_object *object, uint64_t value)
{
    if (object == nullptr) {
        return nullptr;
    }

    // UINT64_MAX is 20 char long
    char container[UINT64_CHARS] = {0};
    size_t length = (size_t)snprintf(container, sizeof(container), "%" PRIu64, value);

    return ddwaf_object_stringl(object, container, length);
}

ddwaf_object *ddwaf_object_unsigned_force(ddwaf_object *object, uint64_t value)
{
    if (object == nullptr) {
        return nullptr;
    }

    *object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_UNSIGNED};
    object->uintValue = value;

    return object;
}

ddwaf_object *ddwaf_object_signed_force(ddwaf_object *object, int64_t value)
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

static bool ddwaf_object_insert(ddwaf_object *array, ddwaf_object object)
{
    // We preallocate 8 entries
    if (array->nbEntries == 0) {
        array->array = (ddwaf_object *)malloc(8 * sizeof(ddwaf_object));
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

        size_t size = (size_t)(array->nbEntries + 8);
        ddwaf_object *newArray =
            (ddwaf_object *)realloc((void *)array->array, size * sizeof(ddwaf_object));
        if (newArray == nullptr) {
            DDWAF_DEBUG("Allocation failure when trying to lengthen a map or an array");
            return false;
        }
        array->array = newArray;
    }

    memcpy(&((ddwaf_object *)array->array)[array->nbEntries], &object, sizeof(ddwaf_object));
    array->nbEntries += 1;
    return true;
}

bool ddwaf_object_array_add(ddwaf_object *array, ddwaf_object *object)
{
    if (array == nullptr || array->type != DDWAF_OBJ_ARRAY) {
        DDWAF_DEBUG("Invalid call, this API can only be called with an array as first parameter");
        return false;
    } else if (object == nullptr || object->type == DDWAF_OBJ_INVALID) {
        DDWAF_DEBUG("Tried to add an invalid entry to an array");
        return false;
    }
    return ddwaf_object_insert(array, *object);
}

bool ddwaf_object_map_add_helper(
    ddwaf_object *map, const char *key, size_t length, ddwaf_object object)
{
    if (length == SIZE_MAX) {
        DDWAF_DEBUG("invalid key length: %zu", length);
        return false;
    }

    char *name = (char *)malloc((length + 1) * sizeof(char));
    if (name == nullptr) {
        DDWAF_DEBUG("Allocation failure when trying to allocate the map key");
        return false;
    }

    memcpy(name, key, length);
    name[length] = '\0';

    object.parameterName = name;
    object.parameterNameLength = length;

    return ddwaf_object_insert(map, object);
}

static inline bool ddwaf_object_map_add_valid(
    ddwaf_object *map, const char *key, ddwaf_object *object)
{
    if (map == nullptr || map->type != DDWAF_OBJ_MAP || key == nullptr) {
        DDWAF_DEBUG("Invalid call, this API can only be called with a map as first parameter");
        return false;
    } else if (key == nullptr) {
        DDWAF_DEBUG("Invalid call, nullptr key");
        return false;
    } else if (object == nullptr || object->type == DDWAF_OBJ_INVALID) {
        DDWAF_DEBUG("Tried to add an invalid entry to a map");
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

void ddwaf_object_free(ddwaf_object *object)
{
    if (object == nullptr || object->type == DDWAF_OBJ_INVALID)
        return;

    free((void *)object->parameterName);

    switch (object->type) {
    case DDWAF_OBJ_MAP:
    case DDWAF_OBJ_ARRAY: {
        ddwaf_object *value = (ddwaf_object *)object->array;
        if (value != nullptr) {
            for (uint64_t i = 0; i < object->nbEntries; ++i) { ddwaf_object_free(&value[i]); }

            free(value);
        }
        break;
    }

    case DDWAF_OBJ_STRING: {
        free((void *)object->stringValue);
    }
    default:
        break;
    }

    ddwaf_object_invalid(object);
}

DDWAF_OBJ_TYPE ddwaf_object_type(ddwaf_object *object)
{
    return object ? object->type : DDWAF_OBJ_INVALID;
}

size_t ddwaf_object_size(ddwaf_object *object)
{
    if (object == nullptr || !ddwaf::object::is_container(object)) {
        return 0;
    }

    return object->nbEntries;
}

size_t ddwaf_object_length(ddwaf_object *object)
{
    if (object == nullptr || object->type != DDWAF_OBJ_STRING) {
        return 0;
    }

    return object->nbEntries;
}

const char *ddwaf_object_get_key(ddwaf_object *object, size_t *length)
{
    if (object == nullptr || object->parameterName == nullptr) {
        return nullptr;
    }

    if (length) {
        *length = object->parameterNameLength;
    }

    return object->parameterName;
}

const char *ddwaf_object_get_string(ddwaf_object *object, size_t *length)
{
    if (object == nullptr || object->type != DDWAF_OBJ_STRING) {
        return nullptr;
    }

    if (length) {
        *length = object->nbEntries;
    }

    return object->stringValue;
}

uint64_t ddwaf_object_get_unsigned(ddwaf_object *object)
{
    if (object == nullptr || object->type != DDWAF_OBJ_UNSIGNED) {
        return 0;
    }

    return object->uintValue;
}

int64_t ddwaf_object_get_signed(ddwaf_object *object)
{
    if (object == nullptr || object->type != DDWAF_OBJ_SIGNED) {
        return 0;
    }

    return object->intValue;
}

bool ddwaf_object_get_bool(ddwaf_object *object)
{
    if (object == nullptr || object->type != DDWAF_OBJ_BOOL) {
        return false;
    }

    return object->boolean;
}

ddwaf_object *ddwaf_object_get_index(ddwaf_object *object, size_t index)
{
    if (object == nullptr || !ddwaf::object::is_container(object) || index >= object->nbEntries) {
        return nullptr;
    }

    return &object->array[index];
}
}
