// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <concepts>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include "dynamic_string.hpp"
#include "object.hpp"
#include "object_type.hpp"
#include "utils.hpp"

namespace ddwaf {
namespace matcher {

enum class match_result : uint8_t {
    unknown,  // No data could be evaluated
    no_match, // Data was evaluated but there was no match
    match     // Data was evaluated and there was a match
};

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
    [[nodiscard]] virtual std::pair<match_result, dynamic_string> match(
        std::string_view str) const = 0;
    [[nodiscard]] virtual std::pair<match_result, dynamic_string> match(object_view obj) const = 0;
};

template <typename T> class base_impl : public base {
public:
    base_impl() = default;
    explicit base_impl(bool convert_strings) : convert_strings_(convert_strings) {}
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

    // Note that callers use this method to filter out values before calling
    // match, so reporting strings as supported here is what makes the
    // conversion within match reachable at all
    [[nodiscard]] bool is_supported_type(object_type type) const override
    {
        // Strings can be evaluated through a conversion, so they must not be
        // filtered out by callers relying on this method
        if (convert_strings_ && (type & object_type::string) != 0) {
            return true;
        }
        return T::is_supported_type_impl(type);
    }

    // Converts a string into the scalar type evaluated by this matcher. Returns
    // an invalid object when the matcher has no scalar type or when the string
    // can't be represented in it.
    [[nodiscard]] static owned_object convert_string_to_compatible_type(std::string_view input)
    {
        using value_type = std::remove_cvref_t<typename T::value_type>;

        // from_string can't produce either of these, so no conversion is
        // possible. Note that the else is required: statements following an
        // if constexpr are instantiated regardless of the condition, which
        // would make from_string<void> ill-formed for the void specialisations.
        if constexpr (std::is_void_v<value_type> || std::is_same_v<value_type, std::string>) {
            return {};
        } else {
            auto [res, value] = from_string<value_type>(input);
            if (!res) {
                return {};
            }

            if constexpr (std::same_as<value_type, bool>) {
                return owned_object::make_boolean(value);
            } else if constexpr (std::is_integral_v<value_type> && std::is_signed_v<value_type>) {
                return owned_object::make_signed(value);
            } else if constexpr (std::is_integral_v<value_type> && std::is_unsigned_v<value_type>) {
                return owned_object::make_unsigned(value);
            } else if constexpr (std::is_floating_point_v<value_type>) {
                return owned_object::make_float(value);
            } else {
                return {};
            }
        }
    }

    // Helper used for testing purposes
    template <typename U>
    [[nodiscard]] std::pair<match_result, dynamic_string> match(const U &data) const
    {
        if constexpr (is_type_in_set_v<U, owned_object, borrowed_object>) {
            return match(object_view{data});
        } else {
            return static_cast<const T *>(this)->match_impl(data);
        }
    }

    [[nodiscard]] std::pair<match_result, dynamic_string> match(std::string_view str) const override
    {
        const auto *ptr = static_cast<const T *>(this);
        if constexpr (T::is_supported_type_impl(object_type::string)) {
            return ptr->match_impl(str);
        }

        if (convert_strings_) {
            auto converted = convert_string_to_compatible_type(str);
            if (converted.is_valid()) {
                return match_scalar(object_view{converted});
            }
        }

        return {match_result::unknown, {}};
    }

    [[nodiscard]] std::pair<match_result, dynamic_string> match(object_view obj) const override
    {
        const auto *ptr = static_cast<const T *>(this);
        if constexpr (T::is_supported_type_impl(object_type::string)) {
            if (obj.is_string()) {
                return ptr->match_impl(obj.as<std::string_view>());
            }
        }

        owned_object converted;
        if (convert_strings_ && obj.is_string()) {
            converted = convert_string_to_compatible_type(obj.as<std::string_view>());
            if (converted.is_valid()) {
                obj = converted;
            }
        }

        return match_scalar(obj);
    }

protected:
    // Evaluates the scalar types natively supported by the matcher, reporting
    // unknown when none of them apply
    [[nodiscard]] std::pair<match_result, dynamic_string> match_scalar(object_view obj) const
    {
        const auto *ptr = static_cast<const T *>(this);
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

        return {match_result::unknown, {}};
    }

    // Evaluate string values by converting them to the scalar type of the
    // matcher; strings which can't be converted are not evaluated at all
    bool convert_strings_{false};
};

} // namespace matcher

using matcher_mapper = std::unordered_map<std::string, std::unique_ptr<matcher::base>>;

} // namespace ddwaf
