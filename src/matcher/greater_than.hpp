// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include "ddwaf.h"
#include "matcher/base.hpp"
#include "utils.hpp"

namespace ddwaf::matcher {

template <typename T>
    requires std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t> || std::is_same_v<T, double>
class greater_than : public base_impl<greater_than<T>> {
public:
    explicit greater_than(T minimum) : minimum_(std::move(minimum)) {}
    ~greater_than() override = default;
    greater_than(const greater_than &) = default;
    greater_than(greater_than &&) noexcept = default;
    greater_than &operator=(const greater_than &) = default;
    greater_than &operator=(greater_than &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "greater_than"; }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        return type == DDWAF_OBJ_SIGNED || type == DDWAF_OBJ_UNSIGNED || type == DDWAF_OBJ_FLOAT;
    }

    template <typename U>
    [[nodiscard]] std::pair<bool, std::string> match_impl(const U &obtained) const
        requires(!std::is_floating_point_v<T>)
    {
        return {std::cmp_greater(obtained, minimum_), {}};
    }

    [[nodiscard]] std::pair<bool, std::string> match_impl(double obtained) const
    {
        return {obtained > minimum_, {}};
    }
    T minimum_;

    friend class base_impl<greater_than<T>>;
};

} // namespace ddwaf::matcher
