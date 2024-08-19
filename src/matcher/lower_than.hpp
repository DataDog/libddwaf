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

template <typename T>
    requires std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t> || std::is_same_v<T, double>
class lower_than : public base_impl<lower_than<T>> {
public:
    explicit lower_than(T maximum) : maximum_(std::move(maximum)) {}
    ~lower_than() override = default;
    lower_than(const lower_than &) = default;
    lower_than(lower_than &&) noexcept = default;
    lower_than &operator=(const lower_than &) = default;
    lower_than &operator=(lower_than &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "lower_than"; }

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
        return {maximum_ > obtained, {}};
    }

    T maximum_;

    friend class base_impl<lower_than<T>>;
};

} // namespace ddwaf::matcher
