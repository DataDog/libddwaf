// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "ddwaf.h"
#include "semver.hpp"
#include "utils.hpp"

namespace {

std::string strtype(int type)
{
    switch (type) {
    case DDWAF_OBJ_MAP:
        return "map";
    case DDWAF_OBJ_ARRAY:
        return "array";
    case DDWAF_OBJ_STRING:
        return "string";
    case DDWAF_OBJ_BOOL:
        return "bool";
    case DDWAF_OBJ_UNSIGNED:
        return "unsigned";
    case DDWAF_OBJ_SIGNED:
        return "signed";
    case DDWAF_OBJ_FLOAT:
        return "float";
    case DDWAF_OBJ_NULL:
        return "null";
    default:
        break;
    }
    return "unknown";
}

} // namespace

namespace ddwaf {

raw_configuration::operator raw_configuration::map() const
{
    if (type != DDWAF_OBJ_MAP) {
        throw bad_cast("map", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return {};
    }

    std::unordered_map<std::string_view, raw_configuration> map;
    map.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++) {
        const raw_configuration &kv = array[i];
        if (kv.parameterName == nullptr) {
            throw malformed_object("invalid key on map entry");
        }

        map.emplace(std::string_view(kv.parameterName, kv.parameterNameLength), kv);
    }

    return map;
}

raw_configuration::operator raw_configuration::vector() const
{
    if (type != DDWAF_OBJ_ARRAY) {
        throw bad_cast("array", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return {};
    }
    return {array, array + nbEntries};
}

raw_configuration::operator raw_configuration::string_set() const
{
    if (type != DDWAF_OBJ_ARRAY) {
        throw bad_cast("array", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return {};
    }

    raw_configuration::string_set set;
    set.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++) {
        if (array[i].type != DDWAF_OBJ_STRING) {
            throw malformed_object("item in array not a string, can't cast to string set");
        }

        set.emplace(array[i].stringValue, array[i].nbEntries);
    }

    return set;
}

raw_configuration::operator std::string_view() const
{
    if (type != DDWAF_OBJ_STRING || stringValue == nullptr) {
        throw bad_cast("string_view", strtype(type));
    }

    return {stringValue, static_cast<size_t>(nbEntries)};
}

raw_configuration::operator std::string() const
{
    switch (type) {
    case DDWAF_OBJ_SIGNED:
        return ddwaf::to_string<std::string>(intValue);
    case DDWAF_OBJ_UNSIGNED:
        return ddwaf::to_string<std::string>(uintValue);
    case DDWAF_OBJ_BOOL:
        return ddwaf::to_string<std::string>(boolean);
    case DDWAF_OBJ_FLOAT:
        return ddwaf::to_string<std::string>(f64);
    case DDWAF_OBJ_STRING:
        if (stringValue == nullptr) {
            break;
        }
        return {stringValue, static_cast<size_t>(nbEntries)};
    default:
        break;
    }

    throw bad_cast("string", strtype(type));
}

raw_configuration::operator uint64_t() const
{
    if (type == DDWAF_OBJ_UNSIGNED) {
        return uintValue;
    }

    if (type == DDWAF_OBJ_SIGNED && intValue >= 0) {
        return intValue;
    }

    // NOLINTBEGIN(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)
    // Closest 64-bit floating-point value to UINT64_MAX
    static constexpr double uint64_max = 0xFFFFFFFFFFFFF800ULL;
    if (type == DDWAF_OBJ_FLOAT && (f64 >= 0.0) && (f64 <= uint64_max) &&
        static_cast<uint64_t>(f64) == f64) {
        return static_cast<uint64_t>(f64);
    }
    // NOLINTEND(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)

    if (type == DDWAF_OBJ_STRING && stringValue != nullptr) {
        auto [res, result] = from_string<uint64_t>({stringValue, static_cast<size_t>(nbEntries)});
        if (res) {
            return result;
        }
    }

    throw bad_cast("unsigned", strtype(type));
}

raw_configuration::operator int64_t() const
{
    if (type == DDWAF_OBJ_SIGNED) {
        return intValue;
    }

    if (type == DDWAF_OBJ_UNSIGNED && uintValue <= std::numeric_limits<int64_t>::max()) {
        return static_cast<int64_t>(uintValue);
    }

    // NOLINTBEGIN(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)
    // Closest 64-bit floating-point value to INT64_MAX
    static constexpr double int64_max = 0x7FFFFFFFFFFFFC00LL;
    static constexpr double int64_min = std::numeric_limits<int64_t>::min();
    if (type == DDWAF_OBJ_FLOAT && f64 >= int64_min && f64 <= int64_max &&
        static_cast<int64_t>(f64) == f64) {
        return static_cast<int64_t>(f64);
    }
    // NOLINTEND(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)

    if (type == DDWAF_OBJ_STRING && stringValue != nullptr) {
        auto [res, result] = from_string<int64_t>({stringValue, static_cast<size_t>(nbEntries)});
        if (res) {
            return result;
        }
    }

    throw bad_cast("signed", strtype(type));
}

raw_configuration::operator double() const
{
    if (type == DDWAF_OBJ_FLOAT) {
        return f64;
    }

    if (type == DDWAF_OBJ_STRING && stringValue != nullptr) {
        auto [res, result] = from_string<double>({stringValue, static_cast<size_t>(nbEntries)});
        if (res) {
            return result;
        }
    }

    throw bad_cast("double", strtype(type));
}

raw_configuration::operator bool() const
{
    if (type == DDWAF_OBJ_BOOL) {
        return boolean;
    }

    if (type == DDWAF_OBJ_STRING && stringValue != nullptr) {
        const std::string_view str_bool{stringValue, static_cast<size_t>(nbEntries)};
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

    throw bad_cast("bool", strtype(type));
}

raw_configuration::operator std::vector<std::string>() const
{
    if (type != DDWAF_OBJ_ARRAY) {
        throw bad_cast("array", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return {};
    }

    std::vector<std::string> data;
    data.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++) {
        data.emplace_back(static_cast<std::string>(raw_configuration(array[i])));
    }

    return data;
}

raw_configuration::operator std::vector<std::string_view>() const
{
    if (type != DDWAF_OBJ_ARRAY) {
        throw bad_cast("array", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return {};
    }

    std::vector<std::string_view> data;
    data.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++) {
        if (array[i].type != DDWAF_OBJ_STRING) {
            throw malformed_object("item in array not a string, can't cast to string_view vector");
        }

        data.emplace_back(array[i].stringValue, array[i].nbEntries);
    }

    return data;
}

raw_configuration::operator std::unordered_map<std::string, std::string>() const
{
    if (type != DDWAF_OBJ_MAP) {
        throw bad_cast("map", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return {};
    }

    std::unordered_map<std::string, std::string> data;
    data.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++) {
        std::string key{
            array[i].parameterName, static_cast<std::size_t>(array[i].parameterNameLength)};
        data.emplace(std::move(key), static_cast<std::string>(raw_configuration(array[i])));
    }

    return data;
}

raw_configuration::operator semantic_version() const
{
    if (type != DDWAF_OBJ_STRING || stringValue == nullptr) {
        throw bad_cast("string", strtype(type));
    }

    return semantic_version{{stringValue, static_cast<size_t>(nbEntries)}};
}

} // namespace ddwaf
