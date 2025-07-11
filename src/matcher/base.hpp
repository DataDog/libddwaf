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

#include "ddwaf.h"
#include "dynamic_string.hpp"

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
    [[nodiscard]] virtual bool is_supported_type(DDWAF_OBJ_TYPE type) const = 0;

    [[nodiscard]] virtual std::pair<bool, dynamic_string> match(const ddwaf_object &obj) const = 0;
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

    [[nodiscard]] bool is_supported_type(DDWAF_OBJ_TYPE type) const override
    {
        return T::is_supported_type_impl(type);
    }

    // Helper used for testing purposes
    template <typename U> [[nodiscard]] std::pair<bool, dynamic_string> match(const U &data) const
    {
        return static_cast<const T *>(this)->match_impl(data);
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match(const ddwaf_object &obj) const override
    {
        const auto *ptr = static_cast<const T *>(this);
        if constexpr (T::is_supported_type_impl(DDWAF_OBJ_STRING)) {
            if (obj.type == DDWAF_OBJ_STRING && obj.stringValue != nullptr) {
                return ptr->match_impl({obj.stringValue, static_cast<std::size_t>(obj.nbEntries)});
            }
        }

        if constexpr (T::is_supported_type_impl(DDWAF_OBJ_SIGNED)) {
            if (obj.type == DDWAF_OBJ_SIGNED) {
                return ptr->match_impl(obj.intValue);
            }
        }

        if constexpr (T::is_supported_type_impl(DDWAF_OBJ_UNSIGNED)) {
            if (obj.type == DDWAF_OBJ_UNSIGNED) {
                return ptr->match_impl(obj.uintValue);
            }
        }

        if constexpr (T::is_supported_type_impl(DDWAF_OBJ_BOOL)) {
            if (obj.type == DDWAF_OBJ_BOOL) {
                return ptr->match_impl(obj.boolean);
            }
        }

        if constexpr (T::is_supported_type_impl(DDWAF_OBJ_FLOAT)) {
            if (obj.type == DDWAF_OBJ_FLOAT) {
                return ptr->match_impl(obj.f64);
            }
        }

        return {false, {}};
    }
};

} // namespace matcher

using matcher_mapper = std::unordered_map<std::string, std::unique_ptr<matcher::base>>;

} // namespace ddwaf
