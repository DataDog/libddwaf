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

#include "matcher/base.hpp"
#include "utils.hpp"

namespace ddwaf::matcher {

template <typename T> class equals : public base_impl<equals<T>> {
public:
    explicit equals(T expected)
        requires(!std::is_floating_point_v<T>)
        : expected_(std::move(expected))
    {}
    ~equals() override = default;
    equals(const equals &) = default;
    equals(equals &&) noexcept = default;
    equals &operator=(const equals &) = default;
    equals &operator=(equals &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "equals"; }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) {
            return type == DDWAF_OBJ_SIGNED || type == DDWAF_OBJ_UNSIGNED;
        }

        if constexpr (std::is_same_v<T, bool>) {
            return type == DDWAF_OBJ_BOOL;
        }

        if constexpr (std::is_same_v<T, std::string>) {
            return type == DDWAF_OBJ_STRING;
        }
    }

    template <typename U>
    [[nodiscard]] std::pair<bool, std::string> match_impl(const U &obtained) const
        requires(!std::is_same_v<T, std::string>)
    {
        if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) {
            return {std::cmp_equal(expected_, obtained), {}};
        } else {
            return {expected_ == obtained, {}};
        }
    }

    [[nodiscard]] std::pair<bool, std::string> match_impl(std::string_view obtained) const
        requires std::is_same_v<T, std::string>
    {
        return {expected_ == obtained, {}};
    }

    T expected_;

    friend class base_impl<equals<T>>;
};

template <> class equals<double> : public base_impl<equals<double>> {
public:
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    equals(double expected, double delta) : expected_(expected), delta_(delta) {}
    ~equals() override = default;
    equals(const equals &) = default;
    equals(equals &&) noexcept = default;
    equals &operator=(const equals &) = default;
    equals &operator=(equals &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "equals"; }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        return type == DDWAF_OBJ_FLOAT;
    }

    [[nodiscard]] std::pair<bool, std::string> match_impl(double obtained) const
    {
        return {std::abs(expected_ - obtained) < delta_, {}};
    }

    double expected_;
    double delta_;

    friend class base_impl<equals<double>>;
};

} // namespace ddwaf::matcher
