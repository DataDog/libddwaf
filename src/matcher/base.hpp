// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "dynamic_string.hpp"
#include "object.hpp"
#include "object_type.hpp"

namespace ddwaf {
namespace matcher {

class regex_prefilter;

class base {
public:
    // The set of object types supported by a matcher, as a bitmap indexed by
    // the value of object_type, so that the type of every iterated object
    // can be checked inline instead of with a virtual call.
    class type_set {
    public:
        template <typename Predicate> static constexpr type_set from_predicate(Predicate pred)
        {
            type_set set;
            for (std::size_t i = 0; i <= std::numeric_limits<uint8_t>::max(); ++i) {
                if (pred(static_cast<object_type>(i))) {
                    set.bits_[i / word_bits] |= uint64_t{1} << (i % word_bits);
                }
            }
            return set;
        }

        [[nodiscard]] constexpr bool contains(object_type type) const
        {
            const auto i = static_cast<std::size_t>(type);
            return ((bits_[i / word_bits] >> (i % word_bits)) & 1) != 0;
        }

    private:
        static constexpr std::size_t word_bits = 64;
        std::array<uint64_t, (std::numeric_limits<uint8_t>::max() + 1) / word_bits> bits_{};
    };

    explicit base(type_set supported_types) : supported_types_(supported_types) {}
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
    [[nodiscard]] bool is_supported_type(object_type type) const
    {
        return supported_types_.contains(type);
    }

    [[nodiscard]] virtual std::pair<bool, dynamic_string> match(std::string_view str) const = 0;
    [[nodiscard]] virtual std::pair<bool, dynamic_string> match(object_view obj) const = 0;

    // A necessary condition for a string to match (see regex_prefilter), if
    // the matcher supports one and build_prefilter has been called
    [[nodiscard]] virtual const regex_prefilter *get_prefilter() const { return nullptr; }
    // Builds the prefilter, once, if the matcher supports one. This is only
    // done for the matchers of rules, which can use it.
    virtual const regex_prefilter *build_prefilter() const { return nullptr; }

private:
    type_set supported_types_;
};

template <typename T> class base_impl : public base {
public:
    base_impl() : base(supported_types()) {}
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

    // Helper used for testing purposes
    template <typename U> [[nodiscard]] std::pair<bool, dynamic_string> match(const U &data) const
    {
        if constexpr (is_type_in_set_v<U, owned_object, borrowed_object>) {
            return match(object_view{data});
        } else {
            return static_cast<const T *>(this)->match_impl(data);
        }
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match(std::string_view str) const override
    {
        const auto *ptr = static_cast<const T *>(this);
        if constexpr (T::is_supported_type_impl(object_type::string)) {
            return ptr->match_impl(str);
        }
        return {false, {}};
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match(object_view obj) const override
    {
        const auto *ptr = static_cast<const T *>(this);
        if constexpr (T::is_supported_type_impl(object_type::string)) {
            if (obj.is_string()) {
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

private:
    static consteval type_set supported_types()
    {
        return type_set::from_predicate(T::is_supported_type_impl);
    }
};

} // namespace matcher

// Matchers built from rules_data or exclusion_data. They are shared so that
// the matchers of unchanged data sets can be reused by subsequent builds.
using matcher_mapper = std::unordered_map<std::string, std::shared_ptr<const matcher::base>>;

} // namespace ddwaf
