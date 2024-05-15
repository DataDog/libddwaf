// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <array>
#include <string>
#include <type_traits>

#include "exception.hpp"
#include "object_view.hpp"
#include "utils.hpp"

namespace ddwaf {

template <typename T>
concept is_unsigned = std::is_integral_v<T> && std::is_unsigned_v<T> && !std::is_same_v<T, bool>;

/*template<typename T>*/
/*concept is_signed = std::is_signed_v<T> && !std::is_same_v<T, bool>;*/

template <typename T>
concept is_floating_point = std::is_floating_point_v<T>;

template <typename T> struct object_view::converter {
    explicit converter(object_view view) : view(view) {}
    T operator()() const
    {
        auto res = view.as<T>();
        if (!res.has_value()) {
            // TODO FIX this
            [[unlikely]] throw bad_cast("unkown", object_type_to_string<std::string>(view.type()));
        }
        return view.as_unchecked<T>();
    }
    object_view view;
};

/*template <> struct object_view::converter<bool> {*/
/*explicit converter(object_view view) : view(view) {}*/
/*bool operator()() const*/
/*{*/
/*if (view.type() == object_type::boolean) {*/
/*[[unlikely]] throw bad_cast("bool", object_type_to_string<std::string>(view.type()));*/
/*}*/
/*return view.as_unchecked<bool>();*/
/*}*/
/*object_view view;*/
/*};*/

template <is_unsigned T> struct object_view::converter<T> {
    explicit converter(object_view view) : view(view) {}
    T operator()() const
    {
        if (view.type() == object_type::uint64) {
            return static_cast<T>(view.as_unchecked<uint64_t>());
        }

        if (view.is_string()) {
            auto [res, result] = from_string<uint64_t>(view.as_unchecked<std::string_view>());
            if (res) {
                return result;
            }
        }

        [[unlikely]] throw bad_cast("unsigned", object_type_to_string<std::string>(view.type()));
    }
    object_view view;
};

/*template <is_signed T>*/
/*struct object_view::converter<T> {*/
/*explicit converter(object_view view) : view(view) {}*/
/*T operator()() const*/
/*{*/
/*if (view.type() == object_type::uint64) {*/
/*[[unlikely]] throw bad_cast("signed", object_type_to_string<std::string>(view.type()));*/
/*}*/
/*return view.as_unchecked<T>();*/
/*}*/
/*object_view view;*/
/*};*/
/*template <is_floating_point T>*/
/*struct object_view::converter<T> {*/
/*explicit converter(object_view view) : view(view) {}*/
/*T operator()() const*/
/*{*/
/*if (view.type() == object_type::float64) {*/
/*[[unlikely]] throw bad_cast("float", object_type_to_string<std::string>(view.type()));*/
/*}*/
/*return view.as_unchecked<T>();*/
/*}*/
/*object_view view;*/
/*};*/

template <> struct object_view::converter<std::string_view> {
    explicit converter(object_view view) : view(view) {}
    std::string_view operator()() const
    {
        if (!view.is_string()) {
            abort();
            [[unlikely]] throw bad_cast("string", object_type_to_string<std::string>(view.type()));
        }
        return view.as_unchecked<std::string_view>();
    }
    object_view view;
};

template <> struct object_view::converter<std::string> {
    explicit converter(object_view view) : view(view) {}
    std::string operator()() const
    {
        switch (view.type()) {
        case object_type::string:
        case object_type::const_string:
        case object_type::small_string:
            return view.as_unchecked<std::string>();
        case object_type::boolean:
            return ddwaf::to_string<std::string>(view.as_unchecked<bool>());
        case object_type::uint64:
            return ddwaf::to_string<std::string>(view.as_unchecked<uint64_t>());
        case object_type::int64:
            return ddwaf::to_string<std::string>(view.as_unchecked<int64_t>());
        case object_type::float64:
            return ddwaf::to_string<std::string>(view.as_unchecked<double>());
        default:
            break;
        }
        abort();
        [[unlikely]] throw bad_cast("string", object_type_to_string<std::string>(view.type()));
    }
    object_view view;
};

template <> struct object_view::converter<object_view::array> {
    explicit converter(object_view view) : view(view) {}
    object_view::array operator()() const
    {
        if (view.type() != object_type::array) {
            [[unlikely]] throw bad_cast("array", object_type_to_string<std::string>(view.type()));
        }
        return view.as_unchecked<object_view::array>();
    }
    object_view view;
};

template <> struct object_view::converter<object_view::map> {
    explicit converter(object_view view) : view(view) {}
    object_view::map operator()() const
    {
        if (view.type() != object_type::map) {
            [[unlikely]] throw bad_cast("map", object_type_to_string<std::string>(view.type()));
        }
        return view.as_unchecked<object_view::map>();
    }
    object_view view;
};

template <> struct object_view::converter<object_view> {
    explicit converter(object_view view) : view(view) {}
    object_view operator()() const { return view; }
    object_view view;
};

template <> struct object_view::converter<std::unordered_map<std::string_view, object_view>> {
    explicit converter(object_view view) : view(view) {}
    std::unordered_map<std::string_view, object_view> operator()() const
    {
        if (view.type() != object_type::map) {
            throw bad_cast("map", object_type_to_string<std::string>(view.type()));
        }

        std::unordered_map<std::string_view, object_view> map;
        auto map_view = view.as_unchecked<object_view::map>();
        for (auto [key, value] : map_view) { map.emplace(key, value); }
        return map;
    }
    object_view view;
};

template <> struct object_view::converter<std::unordered_map<std::string, std::string>> {
    explicit converter(object_view view) : view(view) {}
    std::unordered_map<std::string, std::string> operator()() const
    {
        if (view.type() != object_type::map) {
            throw bad_cast("map", object_type_to_string<std::string>(view.type()));
        }

        std::unordered_map<std::string, std::string> map;
        auto map_view = view.as_unchecked<object_view::map>();
        for (auto [key, value] : map_view) { map.emplace(key, value.convert<std::string>()); }
        return map;
    }
    object_view view;
};

template <> struct object_view::converter<std::vector<std::string>> {
    explicit converter(object_view view) : view(view) {}
    std::vector<std::string> operator()() const
    {
        if (view.type() != object_type::array) {
            throw bad_cast("array", object_type_to_string<std::string>(view.type()));
        }

        std::vector<std::string> vec;
        auto array_view = view.as_unchecked<object_view::array>();
        for (auto value : array_view) { vec.emplace_back(value.convert<std::string>()); }
        return vec;
    }
    object_view view;
};

template <> struct object_view::converter<std::vector<std::string_view>> {
    explicit converter(object_view view) : view(view) {}
    std::vector<std::string_view> operator()() const
    {
        if (view.type() != object_type::array) {
            throw bad_cast("array", object_type_to_string<std::string>(view.type()));
        }

        std::vector<std::string_view> vec;
        auto array_view = view.as_unchecked<object_view::array>();
        for (auto value : array_view) { vec.emplace_back(value.convert<std::string_view>()); }
        return vec;
    }
    object_view view;
};

} // namespace ddwaf
