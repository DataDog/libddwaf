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

#include "object_view.hpp"
#include "utils.hpp"

namespace ddwaf {

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
        // TODO fix this with a proper exception
        throw std::runtime_error("invalid conversion");
    }
    object_view view;
};

} // namespace ddwaf
