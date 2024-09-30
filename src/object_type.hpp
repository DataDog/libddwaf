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
    invalid = 0,
    null = 1 << 7,
    boolean = 1 << 5,
    int64 = 1 << 0,
    uint64 = 1 << 1,
    float64 = 1 << 6,
    string = 1 << 2,
    array = 1 << 3,
    map = 1 << 4,
};

template <typename T>
constexpr object_type operator|(object_type left, T right)
    requires std::is_same_v<T, object_type> || std::is_integral_v<T>
{
    using utype = std::underlying_type_t<object_type>;
    return static_cast<object_type>(static_cast<utype>(left) | static_cast<utype>(right));
}

template <typename T>
constexpr object_type operator&(object_type left, T right)
    requires std::is_same_v<T, object_type> || std::is_integral_v<T>
{
    using utype = std::underlying_type_t<object_type>;
    return static_cast<object_type>(static_cast<utype>(left) & static_cast<utype>(right));
}

template <typename T>
constexpr auto operator<=>(object_type left, T right)
    requires std::is_same_v<T, object_type> || std::is_integral_v<T>
{
    using utype = std::underlying_type_t<object_type>;
    return static_cast<utype>(left) <=> static_cast<utype>(right);
}

template <typename T>
constexpr bool operator==(object_type left, T right)
    requires std::is_same_v<T, object_type> || std::is_integral_v<T>
{
    using utype = std::underlying_type_t<object_type>;
    return static_cast<utype>(left) == static_cast<utype>(right);
}

// Null is not considered a scalar, but also not considered invalid
constexpr inline object_type scalar_object_type = object_type::boolean | object_type::int64 | object_type::uint64 | object_type::float64 | object_type::string;

constexpr inline object_type container_object_type = object_type::array | object_type::map;

inline bool is_scalar(object_type type) {
    return (type & scalar_object_type) != 0;
}

inline bool is_container(object_type type) {
    return (type & container_object_type) != 0;
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
