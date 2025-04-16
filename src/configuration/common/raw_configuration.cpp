// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "object_type.hpp"
#include "semver.hpp"
#include "utils.hpp"

namespace ddwaf {
namespace {

std::string strtype(object_type type)
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
    default:
        break;
    }
    return "unknown";
}

} // namespace

raw_configuration::operator raw_configuration::map() const
{
    if (!view_.is_map()) {
        throw bad_cast("map", strtype(view_.type()));
    }

    if (view_.empty()) {
        return {};
    }

    std::unordered_map<std::string_view, raw_configuration> map;
    map.reserve(view_.size());
    for (auto [key, value] : view_) {
        if (key.empty()) {
            throw malformed_object("invalid key on map entry");
        }
        map.emplace(key.as<std::string_view>(), value);
    }
    return map;
}

raw_configuration::operator raw_configuration::vector() const
{
    if (!view_.is_array()) {
        throw bad_cast("array", strtype(view_.type()));
    }

    if (view_.empty()) {
        return {};
    }
    raw_configuration::vector vec;
    vec.reserve(view_.size());

    for (auto [_, value] : view_) { vec.emplace_back(value); }
    return vec;
}

raw_configuration::operator raw_configuration::string_set() const
{
    if (!view_.is_array()) {
        throw bad_cast("array", strtype(view_.type()));
    }

    if (view_.empty()) {
        return {};
    }

    raw_configuration::string_set set;
    set.reserve(view_.size());

    for (auto [_, value] : view_) {
        if (!value.is_string()) {
            throw malformed_object("item in array not a string, can't cast to string set");
        }
        set.emplace(value.as<std::string_view>());
    }
    return set;
}

raw_configuration::operator std::string_view() const
{
    if (!view_.is_string()) {
        throw bad_cast("string_view", strtype(view_.type()));
    }

    return view_.as<std::string_view>();
}

raw_configuration::operator std::string() const
{
    if (!view_.is_scalar()) {
        throw bad_cast("string", strtype(view_.type()));
    }

    if (view_.is_string() && view_.empty()) {
        return {};
    }

    return view_.convert<std::string>();
}

raw_configuration::operator uint64_t() const
{
    if (view_.is<uint64_t>()) {
        return view_.as<uint64_t>();
    }

    if (view_.is<int64_t>() && view_.as<int64_t>() >= 0) {
        return view_.as<int64_t>();
    }

    // NOLINTBEGIN(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)
    // Closest 64-bit floating-point value to UINT64_MAX
    static constexpr double uint64_max = 0xFFFFFFFFFFFFF800ULL;
    if (view_.is<double>()) {
        auto f64 = view_.as<double>();
        if ((f64 >= 0.0) && (f64 <= uint64_max) && static_cast<uint64_t>(f64) == f64) {
            return static_cast<uint64_t>(f64);
        }
    }
    // NOLINTEND(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)

    if (view_.is_string() && !view_.empty()) {
        auto [res, result] = from_string<uint64_t>(view_.as<std::string_view>());
        if (res) {
            return result;
        }
    }

    throw bad_cast("unsigned", strtype(view_.type()));
}

raw_configuration::operator int64_t() const
{
    if (view_.is<int64_t>()) {
        return view_.as<int64_t>();
    }

    if (view_.is<uint64_t>() && view_.as<uint64_t>() <= std::numeric_limits<int64_t>::max()) {
        return static_cast<int64_t>(view_.as<uint64_t>());
    }

    // NOLINTBEGIN(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)
    // Closest 64-bit floating-point value to INT64_MAX
    static constexpr double int64_max = 0x7FFFFFFFFFFFFC00LL;
    static constexpr double int64_min = std::numeric_limits<int64_t>::min();
    if (view_.is<double>()) {
        auto f64 = view_.as<double>();
        if ((f64 >= int64_min) && (f64 <= int64_max) && static_cast<int64_t>(f64) == f64) {
            return static_cast<int64_t>(f64);
        }
    }
    // NOLINTEND(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)

    if (view_.is_string() && !view_.empty()) {
        auto [res, result] = from_string<int64_t>(view_.as<std::string_view>());
        if (res) {
            return result;
        }
    }

    throw bad_cast("signed", strtype(view_.type()));
}

raw_configuration::operator double() const
{
    if (view_.is<double>()) {
        return view_.as<double>();
    }

    if (view_.is_string() && !view_.empty()) {
        auto [res, result] = from_string<double>(view_.as<std::string_view>());
        if (res) {
            return result;
        }
    }

    throw bad_cast("double", strtype(view_.type()));
}

raw_configuration::operator bool() const
{
    if (view_.is<bool>()) {
        return view_.as<bool>();
    }

    if (view_.is_string() && !view_.empty()) {
        const auto str_bool = view_.as<std::string_view>();
        if (str_bool.size() == (sizeof("true") - 1) && (str_bool[0] == 'T' || str_bool[0] == 't') &&
            (str_bool[1] == 'R' || str_bool[1] == 'r') &&
            (str_bool[2] == 'U' || str_bool[2] == 'u') &&
            (str_bool[3] == 'E' || str_bool[3] == 'e')) {
            return true;
        }

        if (str_bool.size() == (sizeof("false") - 1) &&
            (str_bool[0] == 'F' || str_bool[0] == 'f') &&
            (str_bool[1] == 'A' || str_bool[1] == 'a') &&
            (str_bool[2] == 'L' || str_bool[2] == 'l') &&
            (str_bool[3] == 'S' || str_bool[3] == 's') &&
            (str_bool[4] == 'E' || str_bool[4] == 'e')) {
            return false;
        }
    }

    throw bad_cast("bool", strtype(view_.type()));
}

raw_configuration::operator std::vector<std::string>() const
{
    if (!view_.is_array()) {
        throw bad_cast("array", strtype(view_.type()));
    }

    if (view_.empty()) {
        return {};
    }

    std::vector<std::string> vec;
    vec.reserve(view_.size());

    for (auto [_, value] : view_) {
        const raw_configuration item{value};
        vec.emplace_back(static_cast<std::string>(item));
    }
    return vec;
}

raw_configuration::operator std::vector<std::string_view>() const
{
    if (!view_.is_array()) {
        throw bad_cast("array", strtype(view_.type()));
    }

    if (view_.empty()) {
        return {};
    }

    std::vector<std::string_view> vec;
    vec.reserve(view_.size());

    for (auto [_, value] : view_) {
        if (!value.is_string()) {
            throw malformed_object("item in array not a string, can't cast to string_view vector");
        }
        vec.emplace_back(value.as<std::string_view>());
    }
    return vec;
}

raw_configuration::operator std::unordered_map<std::string, std::string>() const
{
    if (!view_.is_map()) {
        throw bad_cast("map", strtype(view_.type()));
    }

    if (view_.empty()) {
        return {};
    }

    std::unordered_map<std::string, std::string> map;
    map.reserve(view_.size());
    for (auto [key, value] : view_) {
        if (key.empty()) {
            throw malformed_object("invalid key on map entry");
        }
        const raw_configuration item{value};
        map.emplace(key.as<std::string_view>(), static_cast<std::string>(item));
    }
    return map;
}

raw_configuration::operator semantic_version() const
{
    if (!view_.is_string()) {
        throw bad_cast("string", strtype(view_.type()));
    }

    return semantic_version{view_.as<std::string_view>()};
}

} // namespace ddwaf
