// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string_view>
#include <type_traits>
#include <utility>

#include "matcher/base.hpp"

namespace ddwaf::matcher {

template <typename T = void> class equals : public base_impl<equals<T>> {
public:
    static constexpr std::string_view matcher_name = "equals";
    static constexpr std::string_view negated_matcher_name = "!equals";

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
    static constexpr bool is_supported_type_impl(object_type type)
    {
        if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) {
            return type == object_type::int64 || type == object_type::uint64;
        }

        if constexpr (std::is_same_v<T, bool>) {
            return type == object_type::boolean;
        }

        if constexpr (std::is_same_v<T, std::string>) {
            return (type & object_type::string) != 0;
        }
    }

    template <typename U>
    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(const U &obtained) const
        requires(std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) && std::is_integral_v<U>
    {
        return {std::cmp_equal(expected_, obtained), {}};
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(bool obtained) const
        requires std::is_same_v<T, bool>
    {
        return {expected_ == obtained, {}};
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(std::string_view obtained) const
        requires std::is_same_v<T, std::string>
    {
        return {expected_ == obtained, {}};
    }

    T expected_;

    friend class base_impl<equals<T>>;
};

template <> class equals<double> : public base_impl<equals<double>> {
public:
    static constexpr std::string_view matcher_name = "equals";
    static constexpr std::string_view negated_matcher_name = "!equals";

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    equals(double expected, double delta) : expected_(expected), delta_(delta) {}
    ~equals() override = default;
    equals(const equals &) = default;
    equals(equals &&) noexcept = default;
    equals &operator=(const equals &) = default;
    equals &operator=(equals &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr bool is_supported_type_impl(object_type type)
    {
        return type == object_type::float64;
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(double obtained) const
    {
        return {std::abs(expected_ - obtained) < delta_, {}};
    }

    double expected_;
    double delta_;

    friend class base_impl<equals<double>>;
};

template <> class equals<void> : public base_impl<equals<void>> {
public:
    static constexpr std::string_view matcher_name = "equals";
    static constexpr std::string_view negated_matcher_name = "!equals";

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    ~equals() override = default;

protected:
    equals() = default;
    equals(const equals &) = default;
    equals(equals &&) noexcept = default;
    equals &operator=(const equals &) = default;
    equals &operator=(equals &&) noexcept = default;

    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr bool is_supported_type_impl(object_type /*type*/) { return false; }
    [[nodiscard]] static std::pair<bool, dynamic_string> match_impl() { return {}; }

    friend class base_impl<equals<void>>;
};

} // namespace ddwaf::matcher
