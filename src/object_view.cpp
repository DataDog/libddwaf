// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <charconv>
#include <cinttypes>

#include "ddwaf.h"
#include "exception.hpp"
#include "object_view.hpp"

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
    default:
        break;
    }
    return "null";
}

} // namespace

object_view::operator object_view::map() const
{
    if (!is_map()) {
        throw bad_cast("map", strtype(type()));
    }

    if (ptr_->array == nullptr || ptr_->nbEntries == 0) {
        return {};
    }

    std::unordered_map<std::string_view, object_view> map;
    map.reserve(ptr_->nbEntries);
    for (auto kv : *this) {
        if (!kv.has_key()) {
            throw malformed_object("invalid key on map entry");
        }
        map.emplace(kv.key(), kv);
    }

    return map;
}

object_view::operator object_view::vector() const
{
    if (!is_array()) {
        throw bad_cast("array", strtype(type()));
    }

    if (ptr_->array == nullptr || ptr_->nbEntries == 0) {
        return {};
    }
    return std::vector<object_view>(ptr_->array, ptr_->array + ptr_->nbEntries);
}

object_view::operator object_view::string_set() const
{
    if (!is_array()) {
        throw bad_cast("array", strtype(type()));
    }

    if (ptr_->array == nullptr || ptr_->nbEntries == 0) {
        return {};
    }

    object_view::string_set set;
    set.reserve(ptr_->nbEntries);
    for (auto kv : *this) {
        if (!kv.is_string()) {
            throw malformed_object("item in array not a string, can't cast to string set");
        }

        set.emplace(std::string_view(kv));
    }

    return set;
}

object_view::operator std::string_view() const
{
    if (!is_string() || ptr_->stringValue == nullptr) {
        throw bad_cast("string", strtype(type()));
    }

    return {ptr_->stringValue, static_cast<size_t>(ptr_->nbEntries)};
}

object_view::operator std::string() const
{
    if (!is_string() || ptr_->stringValue == nullptr) {
        throw bad_cast("string", strtype(type()));
    }

    return {ptr_->stringValue, static_cast<size_t>(ptr_->nbEntries)};
}

object_view::operator uint64_t() const
{
    if (is_unsigned()) {
        return ptr_->uintValue;
    }

    if (is_string() && ptr_->stringValue != nullptr) {
        uint64_t result;
        const auto *end{&ptr_->stringValue[ptr_->nbEntries]};
        auto [endConv, err] = std::from_chars(ptr_->stringValue, end, result);
        if (err == std::errc{} && endConv == end) {
            return result;
        }
    }

    throw bad_cast("unsigned", strtype(type()));
}

object_view::operator int64_t() const
{
    if (is_signed()) {
        return ptr_->intValue;
    }

    if (is_string() && ptr_->stringValue != nullptr) {
        uint64_t result;
        const auto *end{&ptr_->stringValue[ptr_->nbEntries]};
        auto [endConv, err] = std::from_chars(ptr_->stringValue, end, result);
        if (err == std::errc{} && endConv == end) {
            return result;
        }
    }

    throw bad_cast("signed", strtype(type()));
}

object_view::operator bool() const
{
    if (is_boolean()) {
        return ptr_->boolean;
    }

    if (is_string() && ptr_->stringValue != nullptr) {
        std::string_view str_bool{ptr_->stringValue, length()};
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

    throw bad_cast("bool", strtype(type()));
}

object_view::operator std::vector<std::string>() const
{
    if (!is_array()) {
        throw bad_cast("array", strtype(type()));
    }

    if (ptr_->array == nullptr || ptr_->nbEntries == 0) {
        return {};
    }

    std::vector<std::string> data;
    data.reserve(ptr_->nbEntries);
    for (auto kv : *this) {
        if (!kv.is_string()) {
            throw malformed_object("item in array not a string, can't cast to string set");
        }

        data.emplace_back(std::string(kv));
    }

    return data;
}

object_view::operator std::vector<std::string_view>() const
{
    if (!is_array()) {
        throw bad_cast("array", strtype(type()));
    }

    if (ptr_->array == nullptr || ptr_->nbEntries == 0) {
        return {};
    }

    std::vector<std::string_view> data;
    data.reserve(ptr_->nbEntries);
    for (auto kv : *this) {
        if (!kv.is_string()) {
            throw malformed_object("item in array not a string, can't cast to string set");
        }

        data.emplace_back(std::string_view(kv));
    }

    return data;
}

} // namespace ddwaf
