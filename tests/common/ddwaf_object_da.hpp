// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#pragma once

#include "memory_resource.hpp"
#include "object.hpp"
#include "pointer.hpp"

namespace ddwaf::test {

class ddwaf_object_da {
public:
    static owned_object make_null() { return owned_object::make_null(); }

    static owned_object make_boolean(bool value) { return owned_object::make_boolean(value); }

    static owned_object make_signed(int64_t value) { return owned_object::make_signed(value); }

    static owned_object make_unsigned(uint64_t value) { return owned_object::make_unsigned(value); }

    static owned_object make_float(double value) { return owned_object::make_float(value); }

    static owned_object make_string_literal(const char *str, std::uint32_t len)
    {
        return owned_object::make_string_literal(str, len);
    }

    static owned_object make_string_literal(std::string_view str)
    {
        return owned_object::make_string_literal(str.data(), str.size());
    }

    static owned_object make_string_nocopy(
        const char *str, std::uint32_t len, nonnull_ptr<memory::memory_resource> alloc)
    {
        return owned_object::make_string_nocopy(str, len, alloc);
    }

    static owned_object make_string_nocopy(const char *str, std::uint32_t len)
    {
        return owned_object::make_string_nocopy(str, len, memory::get_default_resource());
    }

    static owned_object make_string(
        const char *str, std::uint32_t len, nonnull_ptr<memory::memory_resource> alloc)
    {
        return owned_object::make_string(str, len, alloc);
    }

    static owned_object make_string(const char *str, std::uint32_t len)
    {
        return owned_object::make_string(str, len, memory::get_default_resource());
    }

    static owned_object make_string(
        std::string_view str, nonnull_ptr<memory::memory_resource> alloc)
    {
        return owned_object::make_string(str, alloc);
    }

    static owned_object make_string(std::string_view str)
    {
        return owned_object::make_string(str, memory::get_default_resource());
    }

    static owned_object make_array(uint16_t capacity, nonnull_ptr<memory::memory_resource> alloc)
    {
        return owned_object::make_array(capacity, alloc);
    }

    static owned_object make_array(uint16_t capacity = 0)
    {
        return owned_object::make_array(capacity, memory::get_default_resource());
    }

    static owned_object make_map(uint16_t capacity, nonnull_ptr<memory::memory_resource> alloc)
    {
        return owned_object::make_map(capacity, alloc);
    }

    static owned_object make_map(uint16_t capacity = 0)
    {
        return owned_object::make_map(capacity, memory::get_default_resource());
    }
};

// Test-only wrappers for object_builder that use default allocator
namespace object_builder_da {
using all_types = object_builder::all_types;
using key_value = object_builder::key_value;

inline owned_object array(std::initializer_list<all_types> list = {})
{
    return object_builder::array(list, memory::get_default_resource());
}

inline owned_object map(std::initializer_list<key_value> list = {})
{
    return object_builder::map(list, memory::get_default_resource());
}
} // namespace object_builder_da

} // namespace ddwaf::test
