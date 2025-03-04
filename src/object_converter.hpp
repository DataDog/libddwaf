// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>

#include "object_view.hpp"
#include "utils.hpp"

namespace ddwaf {

template <> struct object_converter<std::string> {
    explicit object_converter(object_view view) : view(view) {}
    std::string operator()() const
    {
        switch (view.type()) {
        case object_type::string:
            return view.as<std::string>();
        case object_type::boolean:
            return ddwaf::to_string<std::string>(view.as<bool>());
        case object_type::uint64:
            return ddwaf::to_string<std::string>(view.as<uint64_t>());
        case object_type::int64:
            return ddwaf::to_string<std::string>(view.as<int64_t>());
        case object_type::float64:
            return ddwaf::to_string<std::string>(view.as<double>());
        default:
            break;
        }
        return {};
    }
    object_view view;
};

} // namespace ddwaf
