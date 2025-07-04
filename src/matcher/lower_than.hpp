// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string_view>
#include <type_traits>
#include <utility>

#include "ddwaf.h"
#include "matcher/base.hpp"

namespace ddwaf::matcher {

template <typename T = void> class lower_than : public base_impl<lower_than<T>> {
public:
    static constexpr std::string_view matcher_name = "lower_than";
    static constexpr std::string_view negated_matcher_name = "!lower_than";

    explicit lower_than(T maximum)
        requires std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t> ||
                 std::is_same_v<T, double>
        : maximum_(std::move(maximum))
    {}
    ~lower_than() override = default;
    lower_than(const lower_than &) = default;
    lower_than(lower_than &&) noexcept = default;
    lower_than &operator=(const lower_than &) = default;
    lower_than &operator=(lower_than &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        return type == DDWAF_OBJ_SIGNED || type == DDWAF_OBJ_UNSIGNED || type == DDWAF_OBJ_FLOAT;
    }

    template <typename U>
    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(const U &obtained) const
        requires(!std::is_floating_point_v<T>)
    {
        return {std::cmp_less(obtained, maximum_), {}};
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(double obtained) const
    {
        return {obtained < maximum_, {}};
    }

    T maximum_;

    friend class base_impl<lower_than<T>>;
};

template <> class lower_than<void> : public base_impl<lower_than<void>> {
public:
    static constexpr std::string_view matcher_name = "lower_than";
    static constexpr std::string_view negated_matcher_name = "!lower_than";

    ~lower_than() override = default;

protected:
    lower_than() = default;
    lower_than(const lower_than &) = default;
    lower_than(lower_than &&) noexcept = default;
    lower_than &operator=(const lower_than &) = default;
    lower_than &operator=(lower_than &&) noexcept = default;

    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE /*type*/) { return false; }

    [[nodiscard]] static std::pair<bool, dynamic_string> match_impl() { return {}; }

    friend class base_impl<lower_than<void>>;
};

} // namespace ddwaf::matcher
