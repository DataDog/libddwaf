// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string_view>
#include <type_traits>
#include <unordered_map>

#include "ddwaf.h"
#include "matcher/base.hpp"
#include "utils.hpp"

namespace ddwaf::matcher {

template <typename T> class greater_than : public base_impl<greater_than<T>> {
public:
    explicit greater_than(T expected)
        requires(std::is_integral_v<T> || std::is_floating_point_v<T>)
        : expected_(std::move(expected))
    {}
    ~greater_than() override = default;
    greater_than(const greater_than &) = default;
    greater_than(greater_than &&) noexcept = default;
    greater_than &operator=(const greater_than &) = default;
    greater_than &operator=(greater_than &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "greater-than"; }

    static constexpr DDWAF_OBJ_TYPE supported_type_impl()
    {
        if constexpr (std::is_same_v<T, int64_t>) {
            return DDWAF_OBJ_SIGNED;
        }
        if constexpr (std::is_same_v<T, uint64_t>) {
            return DDWAF_OBJ_UNSIGNED;
        }
        if constexpr (std::is_same_v<T, double>) {
            return DDWAF_OBJ_FLOAT;
        }
    }

    [[nodiscard]] std::pair<bool, std::string> match_impl(const T &obtained) const
    {
        return {expected_ > obtained, {}};
    }

    T expected_;

    friend class base_impl<greater_than<T>>;
};

} // namespace ddwaf::matcher
