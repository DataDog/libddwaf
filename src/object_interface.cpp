// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory_resource>

#include "alloc.hpp"
#include "ddwaf.h"
#include "object.hpp"
#include "object_view.hpp"

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
namespace {
std::pmr::memory_resource *to_memres(ddwaf_allocator *alloc)
{
    if (alloc == nullptr) {
        return std::pmr::new_delete_resource();
    }
    return reinterpret_cast<std::pmr::memory_resource *>(alloc);
}

detail::object &to_ref(ddwaf_object *ptr) { return *reinterpret_cast<detail::object *>(ptr); }

detail::object *to_ptr(ddwaf_object *ptr) { return reinterpret_cast<detail::object *>(ptr); }

borrowed_object to_borrowed(ddwaf_object *ptr, ddwaf_allocator *alloc = nullptr)
{
    return borrowed_object{reinterpret_cast<detail::object *>(ptr), to_memres(alloc)};
}

object_view to_view(const ddwaf_object *ptr)
{
    return {reinterpret_cast<const detail::object *>(ptr)};
}

} // namespace

ddwaf_allocator *ddwaf_allocator_init_default() { return std::pmr::get_default_resource(); }

ddwaf_allocator *ddwaf_allocator_init(
    void *user_data, ddwaf_alloc_fn_type *alloc_fn, ddwaf_free_fn_type *free_fn)
{
    return new user_memory_resource(user_data, alloc_fn, free_fn);
}

void ddwaf_allocator_destroy(ddwaf_allocator *alloc)
{
    if (alloc == std::pmr::get_default_resource()) {
        [[unlikely]] return;
    }
    delete alloc;
}

extern "C" {
ddwaf_object *ddwaf_object_alloc(ddwaf_allocator *alloc)
{
    return reinterpret_cast<ddwaf_object *>(
        ddwaf::detail::alloc_helper<detail::object>(*to_memres(alloc), 1));
}

void ddwaf_object_free(ddwaf_object *object, ddwaf_allocator *alloc)
{
    detail::object_free(to_ptr(object), to_memres(alloc));
}

// Destructors
void ddwaf_object_destroy(ddwaf_object *object, ddwaf_allocator *alloc)
{
    if (object == nullptr) {
        return;
    }

    // Call the destructor of owned_object
    detail::object_destroy(to_ref(object), to_memres(alloc));
}

// Constructors
bool ddwaf_object_set_invalid(ddwaf_object *object)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object{}.move();
    return true;
}

bool ddwaf_object_set_null(ddwaf_object *object)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_null().move();
    return true;
}

bool ddwaf_object_set_bool(ddwaf_object *object, bool value)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_boolean(value).move();
    return true;
}

bool ddwaf_object_set_signed(ddwaf_object *object, int64_t value)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_signed(value).move();
    return true;
}

bool ddwaf_object_set_unsigned(ddwaf_object *object, uint64_t value)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_unsigned(value).move();
    return true;
}

bool ddwaf_object_set_float(ddwaf_object *object, double value)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_float(value).move();
    return true;
}

bool ddwaf_object_set_string(
    ddwaf_object *object, const char *str, uint32_t length, ddwaf_allocator *alloc)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_string(str, length, to_memres(alloc)).move();
    return true;
}

bool ddwaf_object_set_string_nocopy(ddwaf_object *object, char *str, uint32_t length)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_string_nocopy(str, length).move();
    return true;
}

bool ddwaf_object_set_const_string(ddwaf_object *object, const char *str, uint32_t length)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_const_string(str, length).move();
    return true;
}

bool ddwaf_object_set_array(ddwaf_object *object, uint16_t capacity, ddwaf_allocator *alloc)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_array(capacity, to_memres(alloc)).move();
    return true;
}

bool ddwaf_object_set_map(ddwaf_object *object, uint16_t capacity, ddwaf_allocator *alloc)
{
    if (object == nullptr) {
        return false;
    }

    to_ref(object) = owned_object::make_map(capacity, to_memres(alloc)).move();
    return true;
}

// Array and map insertion functions
ddwaf_object *ddwaf_object_insert(ddwaf_object *object)
{
    if (object == nullptr) {
        return nullptr;
    }

    auto slot = to_borrowed(object).emplace_back({});
    if (!slot.has_value()) {
        return nullptr;
    }

    return reinterpret_cast<ddwaf_object *>(slot.ptr());
}

ddwaf_object *ddwaf_object_insert_key(
    ddwaf_object *object, const char *key, uint32_t length, ddwaf_allocator *alloc)
{
    if (object == nullptr) {
        return nullptr;
    }

    auto slot = to_borrowed(object, alloc).emplace(std::string_view{key, length}, {});
    if (!slot.has_value()) {
        return nullptr;
    }

    return reinterpret_cast<ddwaf_object *>(slot.ptr());
}

ddwaf_object *ddwaf_object_insert_key_nocopy(ddwaf_object *object, char *key, uint32_t length)
{
    if (object == nullptr) {
        return nullptr;
    }

    auto slot = to_borrowed(object).emplace(owned_object::make_string_nocopy(key, length), {});
    if (!slot.has_value()) {
        return nullptr;
    }

    return reinterpret_cast<ddwaf_object *>(slot.ptr());
}

ddwaf_object *ddwaf_object_insert_const_key(ddwaf_object *object, const char *key, uint32_t length)
{
    if (object == nullptr) {
        return nullptr;
    }

    auto slot = to_borrowed(object).emplace(owned_object::make_const_string(key, length), {});
    if (!slot.has_value()) {
        return nullptr;
    }

    return reinterpret_cast<ddwaf_object *>(slot.ptr());
}

// Getters
ddwaf_object_type ddwaf_object_get_type(const ddwaf_object *object)
{
    return static_cast<ddwaf_object_type>(to_view(object).type());
}

bool ddwaf_object_get_bool(const ddwaf_object *object)
{
    return to_view(object).as<bool>().value_or(false);
}

int64_t ddwaf_object_get_signed(const ddwaf_object *object)
{
    return to_view(object).as<int64_t>().value_or(0);
}

uint64_t ddwaf_object_get_unsigned(const ddwaf_object *object)
{
    return to_view(object).as<uint64_t>().value_or(0);
}
double ddwaf_object_get_float(const ddwaf_object *object)
{
    return to_view(object).as<double>().value_or(0.0);
}
const char *ddwaf_object_get_string(const ddwaf_object *object)
{
    return to_view(object).as<const char *>().value_or(nullptr);
}

uint32_t ddwaf_object_get_length(const ddwaf_object *object) { return to_view(object).length(); }

uint16_t ddwaf_object_get_size(const ddwaf_object *object) { return to_view(object).size(); }

uint16_t ddwaf_object_get_capacity(const ddwaf_object *object)
{
    return to_view(object).capacity();
}
// Container accessors
const ddwaf_object *ddwaf_object_get_index(
    const ddwaf_object *object, uint32_t index, const ddwaf_object **key)
{
    auto view = to_view(object);
    if (view.size() < index) {
        return nullptr;
    }

    if (view.type() == object_type::map) {
        auto map_view = view.as_unchecked<object_view::map>();
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
        auto array_view = view.as_unchecked<object_view::array>();
        auto value_obj = array_view.at(index);
        return reinterpret_cast<const ddwaf_object *>(value_obj.ptr());
    }
    return nullptr;
}

const ddwaf_object *ddwaf_object_find_key(
    const ddwaf_object *object, const char *key, uint32_t length)
{
    auto view = to_view(object);
    if (view.type() == object_type::map) {
        auto map_view = view.as_unchecked<object_view::map>();
        auto value = map_view.at({key, length});
        if (value.is_invalid()) {
            return nullptr;
        }
        return reinterpret_cast<const ddwaf_object *>(value.ptr());
    }
    return nullptr;
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
}
// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
