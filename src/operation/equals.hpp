// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <clock.hpp>
#include <operation/base.hpp>
#include <string_view>
#include <unordered_map>
#include <utils.hpp>

namespace ddwaf::operation {

template <typename T> class equals : public base_impl<equals<T>> {
public:
    using rule_data_type = std::vector<std::pair<std::string_view, uint64_t>>;

    explicit equals(T expected) : expected_(std::move(expected)) {}
    ~equals() override = default;
    equals(const equals &) = default;
    equals(equals &&) noexcept = default;
    equals &operator=(const equals &) = default;
    equals &operator=(equals &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "equals"; }

    template <typename U = T, std::enable_if_t<std::is_same<U, int64_t>::value, bool> = true>
    static constexpr DDWAF_OBJ_TYPE supported_type_impl()
    {
        return DDWAF_OBJ_SIGNED;
    }

    template <typename U = T, std::enable_if_t<std::is_same<U, uint64_t>::value, bool> = true>
    static constexpr DDWAF_OBJ_TYPE supported_type_impl()
    {
        return DDWAF_OBJ_UNSIGNED;
    }

    template <typename U = T, std::enable_if_t<std::is_same<U, bool>::value, bool> = true>
    static constexpr DDWAF_OBJ_TYPE supported_type_impl()
    {
        return DDWAF_OBJ_BOOL;
    }

    template <typename U = T, std::enable_if_t<std::is_same<U, std::string>::value, bool> = true>
    static constexpr DDWAF_OBJ_TYPE supported_type_impl()
    {
        return DDWAF_OBJ_STRING;
    }

    [[nodiscard]] std::pair<bool, memory::string> match_impl(const T &obtained) const
    {
        return {expected_ == obtained, {}};
    }

    template <typename U = T, std::enable_if_t<std::is_same<U, std::string>::value, bool> = true>
    [[nodiscard]] std::pair<bool, memory::string> match_impl(std::string_view obtained) const
    {
        return {expected_ == obtained, {}};
    }

    T expected_;

    friend class base_impl<equals<T>>;
};

} // namespace ddwaf::operation
