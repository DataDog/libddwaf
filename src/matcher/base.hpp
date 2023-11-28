// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ddwaf.h"
#include "event.hpp"
#include "utils.hpp"

namespace ddwaf::matcher {

enum class matcher_type : uint8_t { scalar = 0, structured = 1 };

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
    // Returns a string representing this particular instance of the operator, for example,
    // an operator matching regexes could provide the regex as its string representation.
    [[nodiscard]] virtual std::string_view to_string() const = 0;

    [[nodiscard]] virtual constexpr matcher_type type() const = 0;

    // Scalar matcher methods
    [[nodiscard]] virtual DDWAF_OBJ_TYPE supported_type() const = 0;

    [[nodiscard]] virtual std::pair<bool, std::string> match(const ddwaf_object &obj) const = 0;

    // Structured matcher methods
    [[nodiscard]] virtual constexpr unsigned arity() const = 0;
    [[nodiscard]] virtual constexpr std::vector<std::string_view> arguments() const = 0;

    [[nodiscard]] virtual std::tuple<bool, std::string, std::size_t> match(
        const std::vector<optional_ref<const ddwaf_object>> &args) const = 0;
};

template <typename T> class scalar_base_impl : public base {
public:
    scalar_base_impl() = default;
    ~scalar_base_impl() override = default;
    scalar_base_impl(const scalar_base_impl &) = default;
    scalar_base_impl(scalar_base_impl &&) noexcept = default;
    scalar_base_impl &operator=(const scalar_base_impl &) = default;
    scalar_base_impl &operator=(scalar_base_impl &&) noexcept = default;

    [[nodiscard]] std::string_view name() const override { return T::name_impl(); }

    [[nodiscard]] std::string_view to_string() const override
    {
        return static_cast<const T *>(this)->to_string_impl();
    }

    [[nodiscard]] constexpr matcher_type type() const override { return matcher_type::scalar; }

    [[nodiscard]] DDWAF_OBJ_TYPE supported_type() const override
    {
        return T::supported_type_impl();
    }

    // Helper used for testing purposes
    template <typename U> [[nodiscard]] std::pair<bool, std::string> match(const U &data) const
    {
        return static_cast<const T *>(this)->match_impl(data);
    }

    [[nodiscard]] std::pair<bool, std::string> match(const ddwaf_object &obj) const override
    {
        const auto *ptr = static_cast<const T *>(this);
        if constexpr (T::supported_type_impl() == DDWAF_OBJ_STRING) {
            if (obj.type == DDWAF_OBJ_STRING && obj.stringValue != nullptr) {
                return ptr->match_impl({obj.stringValue, static_cast<std::size_t>(obj.nbEntries)});
            }
        }

        if constexpr (T::supported_type_impl() == DDWAF_OBJ_SIGNED) {
            if (obj.type == DDWAF_OBJ_SIGNED) {
                return ptr->match_impl(obj.intValue);
            }
        }

        if constexpr (T::supported_type_impl() == DDWAF_OBJ_UNSIGNED) {
            if (obj.type == DDWAF_OBJ_UNSIGNED) {
                return ptr->match_impl(obj.uintValue);
            }
        }

        if constexpr (T::supported_type_impl() == DDWAF_OBJ_BOOL) {
            if (obj.type == DDWAF_OBJ_BOOL) {
                return ptr->match_impl(obj.boolean);
            }
        }

        if constexpr (T::supported_type_impl() == DDWAF_OBJ_FLOAT) {
            if (obj.type == DDWAF_OBJ_FLOAT) {
                return ptr->match_impl(obj.f64);
            }
        }

        return {false, {}};
    }

    [[nodiscard]] constexpr unsigned arity() const override { return 0; }
    [[nodiscard]] constexpr std::vector<std::string_view> arguments() const override { return {}; }

    [[nodiscard]] std::tuple<bool, std::string, std::size_t> match(
        const std::vector<optional_ref<const ddwaf_object>> & /*args*/) const override
    {
        return {};
    }
};

template <typename T> class structured_base_impl : public base {
public:
    structured_base_impl() = default;
    ~structured_base_impl() override = default;
    structured_base_impl(const structured_base_impl &) = default;
    structured_base_impl(structured_base_impl &&) noexcept = default;
    structured_base_impl &operator=(const structured_base_impl &) = default;
    structured_base_impl &operator=(structured_base_impl &&) noexcept = default;

    [[nodiscard]] std::string_view name() const override { return T::name_impl(); }

    [[nodiscard]] std::string_view to_string() const override
    {
        return static_cast<const T *>(this)->to_string_impl();
    }

    [[nodiscard]] constexpr matcher_type type() const override { return matcher_type::structured; }

    [[nodiscard]] DDWAF_OBJ_TYPE supported_type() const override { return DDWAF_OBJ_INVALID; }

    [[nodiscard]] std::pair<bool, std::string> match(const ddwaf_object & /*obj*/) const override
    {
        return {};
    }

    [[nodiscard]] unsigned arity() const override { return T::arity_impl(); }
    [[nodiscard]] std::vector<std::string_view> arguments() const override
    {
        return T::arguments_impl();
    }

    [[nodiscard]] std::tuple<bool, std::string, std::size_t> match(
        const std::vector<optional_ref<const ddwaf_object>> &args) const override
    {
        return static_cast<const T *>(this)->match_impl(args);
    }
};

} // namespace ddwaf::matcher
