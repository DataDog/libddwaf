// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include "object_view.hpp"

namespace ddwaf {
namespace matcher {

class base {
public:
    base() = default;
    virtual ~base() = default;
    base(const base &) = default;
    base(base &&) noexcept = default;
    base &operator=(const base &) = default;
    base &operator=(base &&) noexcept = default;

    // Generic matcher methods

    // The return value of this function should outlive the function scope,
    // for example, through a constexpr class static string_view initialised
    // with a literal.
    [[nodiscard]] virtual std::string_view name() const = 0;
    [[nodiscard]] virtual std::string_view negated_name() const = 0;
    // Returns a string representing this particular instance of the operator, for example,
    // an operator matching regexes could provide the regex as its string representation.
    [[nodiscard]] virtual std::string_view to_string() const = 0;

    // Scalar matcher methods
    [[nodiscard]] virtual bool is_supported_type(object_type type) const = 0;

    [[nodiscard]] virtual std::pair<bool, std::string> match(object_view obj) const = 0;
};

template <typename T> class base_impl : public base {
public:
    base_impl() = default;
    ~base_impl() override = default;
    base_impl(const base_impl &) = default;
    base_impl(base_impl &&) noexcept = default;
    base_impl &operator=(const base_impl &) = default;
    base_impl &operator=(base_impl &&) noexcept = default;

    [[nodiscard]] std::string_view name() const override { return T::matcher_name; }
    [[nodiscard]] std::string_view negated_name() const override { return T::negated_matcher_name; }

    [[nodiscard]] std::string_view to_string() const override
    {
        return static_cast<const T *>(this)->to_string_impl();
    }

    [[nodiscard]] bool is_supported_type(object_type type) const override
    {
        return T::is_supported_type_impl(type);
    }

    // Helper used for testing purposes
    template <typename U> [[nodiscard]] std::pair<bool, std::string> match(const U &data) const
    {
        return static_cast<const T *>(this)->match_impl(data);
    }

    [[nodiscard]] std::pair<bool, std::string> match(object_view obj) const override
    {
        const auto *ptr = static_cast<const T *>(this);
        if constexpr (T::is_supported_type_impl(object_type::string)) {
            if (obj.is<std::string_view>()) {
                return ptr->match_impl(obj.as<std::string_view>());
            }
        }

        if constexpr (T::is_supported_type_impl(object_type::int64)) {
            if (obj.type() == object_type::int64) {
                return ptr->match_impl(obj.as<int64_t>());
            }
        }

        if constexpr (T::is_supported_type_impl(object_type::int64)) {
            if (obj.type() == object_type::uint64) {
                return ptr->match_impl(obj.as<uint64_t>());
            }
        }

        if constexpr (T::is_supported_type_impl(object_type::boolean)) {
            if (obj.type() == object_type::boolean) {
                return ptr->match_impl(obj.as<bool>());
            }
        }

        if constexpr (T::is_supported_type_impl(object_type::float64)) {
            if (obj.type() == object_type::float64) {
                return ptr->match_impl(obj.as<double>());
            }
        }

        return {false, {}};
    }
};

} // namespace matcher

using matcher_mapper = std::unordered_map<std::string, std::unique_ptr<matcher::base>>;

} // namespace ddwaf
