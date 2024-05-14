// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <array>
#include <charconv>
#include <iomanip>
#include <string>

#include "exception.hpp"
#include "object_view.hpp"
#include "utils.hpp"

namespace ddwaf {

template <> struct object_view::converter<std::string_view> {
    explicit converter(object_view view) : view(view) {}
    std::string_view operator()() const
    {
        if (!view.is_string()) {
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

} // namespace ddwaf
