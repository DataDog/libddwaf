// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "ddwaf.h"
#include "log.hpp"
#include "object.hpp"
#include "utils.hpp"

using namespace ddwaf;

static_assert(sizeof(ddwaf_object) == sizeof(detail::object));
static_assert(alignof(ddwaf_object) == alignof(detail::object));
static_assert(offsetof(ddwaf_object, via) == offsetof(detail::object, via));
static_assert(offsetof(ddwaf_object, type) == offsetof(detail::object, type));
static_assert(offsetof(ddwaf_object, capacity) == offsetof(detail::object, capacity));
static_assert(offsetof(ddwaf_object, size) == offsetof(detail::object, size));
static_assert(offsetof(ddwaf_object, length) == offsetof(detail::object, length));

static_assert(sizeof(ddwaf_object_kv) == sizeof(detail::object_kv));
static_assert(alignof(ddwaf_object_kv) == alignof(detail::object_kv));
static_assert(offsetof(ddwaf_object_kv, key) == offsetof(detail::object_kv, key));
static_assert(offsetof(ddwaf_object_kv, val) == offsetof(detail::object_kv, val));

// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
extern "C" {
namespace {
// Maximum number of characters required to represent a 64 bit integer as a string
// 20 bytes for UINT64_MAX or INT64_MIN + null byte
constexpr size_t UINT64_CHARS = 21;
} // namespace

// Memory management - alloc / free
/*ddwaf_object *ddwaf_object_alloc(ddwaf_allocator *alloc)*/
/*{*/

/*}*/

/*void ddwaf_object_free(ddwaf_object *object, ddwaf_allocator *alloc)*/
/*{*/

/*}*/

// Destructors
void ddwaf_object_destroy(ddwaf_object *object, ddwaf_allocator * /*alloc*/)
{
    if (object == nullptr) {
        return;
    }

    // Call the destructor of owned_object
    owned_object::from_native(reinterpret_cast<detail::object *>(object));
}

// Constructors
bool ddwaf_object_set_invalid(ddwaf_object *object)
{
    if (object == nullptr) {
        return false;
    }

    *reinterpret_cast<detail::object *>(object) = owned_object::make_invalid().move();
    return true;
}

bool ddwaf_object_set_null(ddwaf_object *object)
{
    if (object == nullptr) {
        return false;
    }

    *reinterpret_cast<detail::object *>(object) = owned_object::make_null().move();
    return true;
}

bool ddwaf_object_set_bool(ddwaf_object *object, bool value)
{
    if (object == nullptr) {
        return false;
    }

    *reinterpret_cast<detail::object *>(object) = owned_object::make_boolean(value).move();
    return true;
}

bool ddwaf_object_set_signed(ddwaf_object *object, int64_t value)
{
    if (object == nullptr) {
        return false;
    }

    *reinterpret_cast<detail::object *>(object) = owned_object::make_signed(value).move();
    return true;
}

bool ddwaf_object_set_unsigned(ddwaf_object *object, uint64_t value)
{
    if (object == nullptr) {
        return false;
    }

    *reinterpret_cast<detail::object *>(object) = owned_object::make_unsigned(value).move();
    return true;
}

bool ddwaf_object_set_float(ddwaf_object *object, double value)
{
    if (object == nullptr) {
        return false;
    }

    *reinterpret_cast<detail::object *>(object) = owned_object::make_float(value).move();
    return true;
}

bool ddwaf_object_set_string(
    ddwaf_object *object, const char *str, uint32_t length, ddwaf_allocator * /*alloc*/)
{
    if (object == nullptr) {
        return false;
    }

    std::string_view to_copy{str, length};
    *reinterpret_cast<detail::object *>(object) = owned_object::make_string(to_copy).move();
    return true;
}

bool ddwaf_object_set_const_string(ddwaf_object *object, const char *str, uint32_t length)
{
    if (object == nullptr) {
        return false;
    }

    *reinterpret_cast<detail::object *>(object) = owned_object::make_string(str, length).move();
    return true;
}

bool ddwaf_object_set_array(ddwaf_object *object, uint16_t capacity, ddwaf_allocator * /*alloc*/)
{
    if (object == nullptr) {
        return false;
    }

    *reinterpret_cast<detail::object *>(object) = owned_object::make_array(capacity).move();
    return true;
}

bool ddwaf_object_set_map(ddwaf_object *object, uint16_t capacity, ddwaf_allocator * /*alloc*/)
{
    if (object == nullptr) {
        return false;
    }

    *reinterpret_cast<detail::object *>(object) = owned_object::make_map(capacity).move();
    return true;
}

// Array and map insertion functions
ddwaf_object *ddwaf_object_insert(ddwaf_object *object)
{
    if (object == nullptr) {
        return nullptr;
    }

    auto borrowed = borrowed_object::from_native(reinterpret_cast<detail::object *>(object));

    auto slot = borrowed.emplace_back({});
    // TODO check for validity
    return reinterpret_cast<ddwaf_object *>(slot.ptr());
}

ddwaf_object *ddwaf_object_insert_key(
    ddwaf_object *object, const char *key, uint32_t length, ddwaf_allocator * /*alloc*/)
{
    if (object == nullptr) {
        return nullptr;
    }

    auto borrowed = borrowed_object::from_native(reinterpret_cast<detail::object *>(object));

    std::string_view key_sv{key, length};
    auto slot = borrowed.emplace(key, {});
    // TODO check for validity
    return reinterpret_cast<ddwaf_object *>(slot.ptr());
}

ddwaf_object *ddwaf_object_insert_const_key(ddwaf_object *object, const char *key, uint32_t length)
{
    // TODO make this 0-copy
    if (object == nullptr) {
        return nullptr;
    }

    auto borrowed = borrowed_object::from_native(reinterpret_cast<detail::object *>(object));

    std::string_view key_sv{key, length};
    auto slot = borrowed.emplace(key, {});
    // TODO check for validity
    return reinterpret_cast<ddwaf_object *>(slot.ptr());
}

// Getters
ddwaf_object_type ddwaf_object_get_type(const ddwaf_object *object)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    return static_cast<ddwaf_object_type>(view.type());
}

bool ddwaf_object_get_bool(const ddwaf_object *object)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    return view.as_nothrow<bool>();
}

int64_t ddwaf_object_get_signed(const ddwaf_object *object)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    return view.as_nothrow<int64_t>();
}

uint64_t ddwaf_object_get_unsigned(const ddwaf_object *object)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    return view.as_nothrow<uint64_t>();
}
double ddwaf_object_get_float(const ddwaf_object *object)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    return view.as_nothrow<double>();
}
const char *ddwaf_object_get_string(const ddwaf_object *object)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    return view.as_nothrow<const char *>();
}

uint32_t ddwaf_object_get_length(const ddwaf_object *object)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    return view.length();
}

uint16_t ddwaf_object_get_size(const ddwaf_object *object)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    return view.size();
}

uint16_t ddwaf_object_get_capacity(const ddwaf_object *object)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    return view.capacity();
}
// Container accessors
const ddwaf_object *ddwaf_object_get_index(
    const ddwaf_object *object, uint32_t index, const ddwaf_object **key)
{
    object_view view{reinterpret_cast<const detail::object *>(object)};
    if (view.size() < index) {
        return nullptr;
    }

    if (view.type() == object_type::map) {
        auto map_view = view.as<map_object_view>();
        auto opt_kv = map_view.at<object_view>(index);
        if (!opt_kv.has_value()) {
            return nullptr;
        }

        auto &[key_obj, value_obj] = opt_kv.value();
        if (key != nullptr) {
            *key = reinterpret_cast<const ddwaf_object *>(key_obj.ptr());
        }
        return reinterpret_cast<const ddwaf_object *>(value_obj.ptr());
    }

    if (view.type() == object_type::array) {
        auto array_view = view.as<array_object_view>();
        auto value_obj = array_view.at(index);
        return reinterpret_cast<const ddwaf_object *>(value_obj.ptr());
    }
}

const ddwaf_object *ddwaf_object_find_key(
    const ddwaf_object *object, const char *key, uint32_t length)
{
    map_object_view view{reinterpret_cast<const detail::object *>(object)};

    auto opt_val = view.at({key, length});
    if (!opt_val.has_value()) {
        return nullptr;
    }
    return reinterpret_cast<const ddwaf_object *>(opt_val->ptr());
}

// Type checkers
bool ddwaf_object_is_invalid(const ddwaf_object *object)
{
    return object != nullptr && object->type == DDWAF_OBJ_INVALID;
}

bool ddwaf_object_is_null(const ddwaf_object *object)
{
    return object != nullptr && object->type == DDWAF_OBJ_NULL;
}

bool ddwaf_object_is_bool(const ddwaf_object *object)
{
    return object != nullptr && object->type == DDWAF_OBJ_BOOL;
}

bool ddwaf_object_is_signed(const ddwaf_object *object)
{
    return object != nullptr && object->type == DDWAF_OBJ_SIGNED;
}

bool ddwaf_object_is_unsigned(const ddwaf_object *object)
{
    return object != nullptr && object->type == DDWAF_OBJ_UNSIGNED;
}

bool ddwaf_object_is_float(const ddwaf_object *object)
{
    return object != nullptr && object->type == DDWAF_OBJ_FLOAT;
}

bool ddwaf_object_is_string(const ddwaf_object *object)
{
    return object != nullptr && (object->type & DDWAF_OBJ_STRING) != 0;
}

bool ddwaf_object_is_array(const ddwaf_object *object)
{
    return object != nullptr && object->type == DDWAF_OBJ_ARRAY;
}

bool ddwaf_object_is_map(const ddwaf_object *object)
{
    return object != nullptr && object->type == DDWAF_OBJ_MAP;
}

bool ddwaf_object_is_container(const ddwaf_object *object)
{
    return object != nullptr && (object->type & 0xE0) != 0;
}

/*ddwaf_object *ddwaf_object_invalid(ddwaf_object *object)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/**object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_INVALID};*/

/*return object;*/
/*}*/

/*ddwaf_object *ddwaf_object_null(ddwaf_object *object)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/**object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_NULL};*/

/*return object;*/
/*}*/

/*static ddwaf_object *ddwaf_object_string_helper(*/
/*ddwaf_object *object, const char *string, size_t length)*/
/*{*/
/*if (length == SIZE_MAX) {*/
/*DDWAF_DEBUG("invalid string length: {}", length);*/
/*return nullptr;*/
/*}*/

/*char *copy = (char *)malloc(length + 1);*/
/*if (copy == nullptr) {*/
/*return nullptr;*/
/*}*/

/*memcpy(copy, string, length);*/
/*copy[length] = '\0';*/

/**object = {nullptr, 0, {copy}, length, DDWAF_OBJ_STRING};*/

/*return object;*/
/*}*/

/*ddwaf_object *ddwaf_object_string(ddwaf_object *object, const char *string)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/*if (string == nullptr) {*/
/*DDWAF_DEBUG("tried to create a string from a nullptr pointer");*/
/*return nullptr;*/
/*}*/
/*return ddwaf_object_string_helper(object, string, strlen(string));*/
/*}*/

/*ddwaf_object *ddwaf_object_stringl(ddwaf_object *object, const char *string, size_t length)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/*if (string == nullptr) {*/
/*DDWAF_DEBUG("Tried to create a string from a nullptr pointer");*/
/*return nullptr;*/
/*}*/

/*return ddwaf_object_string_helper(object, string, length);*/
/*}*/

/*ddwaf_object *ddwaf_object_stringl_nc(ddwaf_object *object, const char *string, size_t length)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/*if (string == nullptr) {*/
/*DDWAF_DEBUG("Tried to create a string from an nullptr pointer");*/
/*return nullptr;*/
/*}*/

/**object = {nullptr, 0, {string}, length, DDWAF_OBJ_STRING};*/

/*return object;*/
/*}*/

/*ddwaf_object *ddwaf_object_string_from_signed(ddwaf_object *object, int64_t value)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/*// INT64_MIN is 20 char long*/
/*char container[UINT64_CHARS] = {0};*/
/*const auto length = (size_t)snprintf(container, sizeof(container), "%" PRId64, value);*/

/*return ddwaf_object_stringl(object, container, length);*/
/*}*/

/*ddwaf_object *ddwaf_object_string_from_unsigned(ddwaf_object *object, uint64_t value)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/*// UINT64_MAX is 20 char long*/
/*char container[UINT64_CHARS] = {0};*/
/*const auto length = (size_t)snprintf(container, sizeof(container), "%" PRIu64, value);*/

/*return ddwaf_object_stringl(object, container, length);*/
/*}*/

/*ddwaf_object *ddwaf_object_unsigned(ddwaf_object *object, uint64_t value)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/**object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_UNSIGNED};*/
/*object->uintValue = value;*/

/*return object;*/
/*}*/

/*ddwaf_object *ddwaf_object_signed(ddwaf_object *object, int64_t value)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/**object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_SIGNED};*/
/*object->intValue = value;*/

/*return object;*/
/*}*/

/*ddwaf_object *ddwaf_object_bool(ddwaf_object *object, bool value)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/**object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_BOOL};*/
/*object->boolean = value;*/

/*return object;*/
/*}*/

/*ddwaf_object *ddwaf_object_float(ddwaf_object *object, double value)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/**object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_FLOAT};*/
/*object->f64 = value;*/

/*return object;*/
/*}*/

/*ddwaf_object *ddwaf_object_array(ddwaf_object *object)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/**object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_ARRAY};*/

/*return object;*/
/*}*/

/*ddwaf_object *ddwaf_object_map(ddwaf_object *object)*/
/*{*/
/*if (object == nullptr) {*/
/*return nullptr;*/
/*}*/

/**object = {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_MAP};*/

/*return object;*/
/*}*/

/*static bool ddwaf_object_insert(ddwaf_object *array, ddwaf_object object)*/
/*{*/
/*// We preallocate 8 entries*/
/*if (array->nbEntries == 0) {*/
/*array->array = (ddwaf_object *)malloc(8 * sizeof(ddwaf_object));*/
/*if (array->array == nullptr) {*/
/*DDWAF_DEBUG("Allocation failure when trying to initialize a map or an array");*/
/*return false;*/
/*}*/
/*}*/
/*// If we're exceeding our preallocation, add 8 more*/
/*else if ((array->nbEntries & 0x7) == 0) {*/
/*if (array->nbEntries + 8 > SIZE_MAX / sizeof(ddwaf_object)) {*/
/*return false;*/
/*}*/

/*const auto size = (size_t)(array->nbEntries + 8);*/
/*auto *newArray = (ddwaf_object *)realloc((void *)array->array, size * sizeof(ddwaf_object));*/
/*if (newArray == nullptr) {*/
/*DDWAF_DEBUG("Allocation failure when trying to lengthen a map or an array");*/
/*return false;*/
/*}*/
/*array->array = newArray;*/
/*}*/

/*memcpy(&((ddwaf_object *)array->array)[array->nbEntries], &object, sizeof(ddwaf_object));*/
/*array->nbEntries += 1;*/
/*return true;*/
/*}*/

/*bool ddwaf_object_array_add(ddwaf_object *array, ddwaf_object *object)*/
/*{*/
/*if (array == nullptr || array->type != DDWAF_OBJ_ARRAY) {*/
/*DDWAF_DEBUG("Invalid call, this API can only be called with an array as first parameter");*/
/*return false;*/
/*}*/
/*if (object == nullptr) {*/
/*DDWAF_DEBUG("Tried to add a null object to an array");*/
/*return false;*/
/*}*/
/*return ddwaf_object_insert(array, *object);*/
/*}*/

/*bool ddwaf_object_map_add_helper(*/
/*ddwaf_object *map, const char *key, size_t length, ddwaf_object object)*/
/*{*/
/*if (length == SIZE_MAX) {*/
/*DDWAF_DEBUG("invalid key length: {}", length);*/
/*return false;*/
/*}*/

/*char *name = (char *)malloc((length + 1) * sizeof(char));*/
/*if (name == nullptr) {*/
/*DDWAF_DEBUG("Allocation failure when trying to allocate the map key");*/
/*return false;*/
/*}*/

/*memcpy(name, key, length);*/
/*name[length] = '\0';*/

/*object.parameterName = name;*/
/*object.parameterNameLength = length;*/

/*if (!ddwaf_object_insert(map, object)) {*/
/*free((void *)object.parameterName);*/
/*return false;*/
/*}*/
/*return true;*/
/*}*/

/*static inline bool ddwaf_object_map_add_valid(*/
/*ddwaf_object *map, const char *key, ddwaf_object *object)*/
/*{*/
/*if (map == nullptr || map->type != DDWAF_OBJ_MAP || key == nullptr) {*/
/*DDWAF_DEBUG("Invalid call, this API can only be called with a map as first parameter");*/
/*return false;*/
/*}*/
/*if (key == nullptr) {*/
/*DDWAF_DEBUG("Invalid call, nullptr key");*/
/*return false;*/
/*}*/
/*if (object == nullptr) {*/
/*DDWAF_DEBUG("Tried to add a null object to a map");*/
/*return false;*/
/*}*/
/*return true;*/
/*}*/

/*bool ddwaf_object_map_add(ddwaf_object *map, const char *key, ddwaf_object *object)*/
/*{*/
/*if (!ddwaf_object_map_add_valid(map, key, object)) {*/
/*return false;*/
/*}*/
/*return ddwaf_object_map_add_helper(map, key, strlen(key), *object);*/
/*}*/

/*bool ddwaf_object_map_addl(ddwaf_object *map, const char *key, size_t length, ddwaf_object
 * *object)*/
/*{*/
/*if (!ddwaf_object_map_add_valid(map, key, object)) {*/
/*return false;*/
/*}*/
/*return ddwaf_object_map_add_helper(map, key, length, *object);*/
/*}*/

/*bool ddwaf_object_map_addl_nc(*/
/*ddwaf_object *map, const char *key, size_t length, ddwaf_object *object)*/
/*{*/
/*if (!ddwaf_object_map_add_valid(map, key, object)) {*/
/*return false;*/
/*}*/

/*object->parameterName = key;*/
/*object->parameterNameLength = length;*/

/*return ddwaf_object_insert(map, *object);*/
/*}*/

/*// NOLINTNEXTLINE(misc-no-recursion)*/
/*void ddwaf_object_free(ddwaf_object *object)*/
/*{*/
/*if (object == nullptr) {*/
/*return;*/
/*}*/

/*free((void *)object->parameterName);*/

/*switch (object->type) {*/
/*case DDWAF_OBJ_MAP:*/
/*case DDWAF_OBJ_ARRAY: {*/
/*auto *value = (ddwaf_object *)object->array;*/
/*if (value != nullptr) {*/
/*for (uint64_t i = 0; i < object->nbEntries; ++i) { ddwaf_object_free(&value[i]); }*/

/*free(value);*/
/*}*/
/*break;*/
/*}*/

/*case DDWAF_OBJ_STRING: {*/
/*free((void *)object->stringValue);*/
/*}*/
/*default:*/
/*break;*/
/*}*/

/*ddwaf_object_invalid(object);*/
/*}*/

/*DDWAF_OBJ_TYPE ddwaf_object_type(const ddwaf_object *object)*/
/*{*/
/*return object != nullptr ? object->type : DDWAF_OBJ_INVALID;*/
/*}*/

/*size_t ddwaf_object_size(const ddwaf_object *object)*/
/*{*/
/*if (object == nullptr || !ddwaf::is_container(object)) {*/
/*return 0;*/
/*}*/

/*return object->nbEntries;*/
/*}*/

/*size_t ddwaf_object_length(const ddwaf_object *object)*/
/*{*/
/*if (object == nullptr || object->type != DDWAF_OBJ_STRING) {*/
/*return 0;*/
/*}*/

/*return object->nbEntries;*/
/*}*/

/*const char *ddwaf_object_get_key(const ddwaf_object *object, size_t *length)*/
/*{*/
/*if (object == nullptr || object->parameterName == nullptr) {*/
/*return nullptr;*/
/*}*/

/*if (length != nullptr) {*/
/**length = object->parameterNameLength;*/
/*}*/

/*return object->parameterName;*/
/*}*/

/*const char *ddwaf_object_get_string(const ddwaf_object *object, size_t *length)*/
/*{*/
/*if (object == nullptr || object->type != DDWAF_OBJ_STRING) {*/
/*return nullptr;*/
/*}*/

/*if (length != nullptr) {*/
/**length = object->nbEntries;*/
/*}*/

/*return object->stringValue;*/
/*}*/

/*uint64_t ddwaf_object_get_unsigned(const ddwaf_object *object)*/
/*{*/
/*if (object == nullptr || object->type != DDWAF_OBJ_UNSIGNED) {*/
/*return 0;*/
/*}*/

/*return object->uintValue;*/
/*}*/

/*int64_t ddwaf_object_get_signed(const ddwaf_object *object)*/
/*{*/
/*if (object == nullptr || object->type != DDWAF_OBJ_SIGNED) {*/
/*return 0;*/
/*}*/

/*return object->intValue;*/
/*}*/

/*double ddwaf_object_get_float(const ddwaf_object *object)*/
/*{*/
/*if (object == nullptr || object->type != DDWAF_OBJ_FLOAT) {*/
/*return 0;*/
/*}*/

/*return object->f64;*/
/*}*/

/*bool ddwaf_object_get_bool(const ddwaf_object *object)*/
/*{*/
/*if (object == nullptr || object->type != DDWAF_OBJ_BOOL) {*/
/*return false;*/
/*}*/

/*return object->boolean;*/
/*}*/

/*const ddwaf_object *ddwaf_object_get_index(const ddwaf_object *object, size_t index)*/
/*{*/
/*if (object == nullptr || !ddwaf::is_container(object) || index >= object->nbEntries) {*/
/*return nullptr;*/
/*}*/

/*return &object->array[index];*/
/*}*/
}

// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
