// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <compare> // IWYU pragma: keep
#include <cstdint>
#include <string>
#include <type_traits>

namespace ddwaf {

enum class object_type : uint8_t {
    invalid = 0x00,      // 0b00000000
    null = 0x01,         // 0b00000001
    boolean = 0x02,      // 0b00000010
    int64 = 0x03,        // 0b00000011
    uint64 = 0x04,       // 0b00000100
    float64 = 0x05,      // 0b00000101
    string = 0x10,       // 0b00010000
    const_string = 0x11, // 0b00010001
    small_string = 0x12, // 0b00010010
    // string == (type & 0x10) != 0
    // scalar == (type & 0x1e) != 0
    array = 0x20, // 0b00100000
    map = 0x40,   // 0b01000000
    // container == (type & 0xE0) != 0
    // valid == (type & 0xFE) != 0
};

// Null is not considered a scalar, but also not considered invalid
constexpr inline uint8_t scalar_object_type = 0x1E;
constexpr inline uint8_t container_object_type = 0xE0;

template <typename T>
inline object_type operator&(object_type left, T right)
    requires std::is_same_v<T, object_type> || std::is_integral_v<T>
{
    using utype = std::underlying_type_t<object_type>;
    return static_cast<object_type>(static_cast<utype>(left) & static_cast<utype>(right));
}

template <typename T>
inline auto operator<=>(object_type left, T right)
    requires std::is_same_v<T, object_type> || std::is_integral_v<T>
{
    using utype = std::underlying_type_t<object_type>;
    return static_cast<utype>(left) <=> static_cast<utype>(right);
}

template <typename T>
inline bool operator==(object_type left, T right)
    requires std::is_same_v<T, object_type> || std::is_integral_v<T>
{
    using utype = std::underlying_type_t<object_type>;
    return static_cast<utype>(left) == static_cast<utype>(right);
}

template <typename T> inline bool is_compatible_type(object_type /*type*/) { return false; }

template <typename T>
inline bool is_compatible_type(object_type type)
    requires std::is_same_v<T, bool>
{
    return type == object_type::boolean;
}

template <typename T>
inline bool is_compatible_type(object_type type)
    requires std::is_unsigned_v<T> && (!std::is_same_v<T, bool>)
{
    return type == object_type::uint64;
}

template <typename T>
inline bool is_compatible_type(object_type type)
    requires std::is_integral_v<T> && std::is_signed_v<T> && (!std::is_same_v<T, bool>)
{
    return type == object_type::int64;
}

template <typename T>
inline bool is_compatible_type(object_type type)
    requires std::is_floating_point_v<T>
{
    return type == object_type::float64;
}

template <typename T>
inline bool is_compatible_type(object_type type)
    requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view> ||
             std::is_same_v<T, const char *>
{
    return (type & object_type::string) != 0;
}

template <typename T>
T object_type_to_string(object_type type)
    requires std::is_constructible_v<T, const char *>
{
    switch (type) {
    case object_type::map:
        return "map";
    case object_type::array:
        return "array";
    case object_type::string:
    case object_type::const_string:
    case object_type::small_string:
        return "string";
    case object_type::boolean:
        return "bool";
    case object_type::uint64:
        return "unsigned";
    case object_type::int64:
        return "signed";
    case object_type::float64:
        return "float";
    case object_type::null:
        return "null";
    case object_type::invalid:
    default:
        break;
    }
    return "unknown";
}

} // namespace ddwaf
