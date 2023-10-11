// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <clock.hpp>
#include <matcher/base.hpp>
#include <string_view>
#include <unordered_map>
#include <utils.hpp>

namespace ddwaf::matcher {

class exact_match : public base_impl<exact_match> {
public:
    using rule_data_type = std::vector<std::pair<std::string_view, uint64_t>>;

    exact_match() = default;
    explicit exact_match(std::vector<std::string> &&data);
    explicit exact_match(const rule_data_type &data);
    ~exact_match() override = default;
    exact_match(const exact_match &) = default;
    exact_match(exact_match &&) = default;
    exact_match &operator=(const exact_match &) = default;
    exact_match &operator=(exact_match &&) = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "exact_match"; }
    static constexpr DDWAF_OBJ_TYPE supported_type_impl() { return DDWAF_OBJ_STRING; }

    [[nodiscard]] std::pair<bool, memory::string> match_impl(std::string_view str) const;

    std::vector<std::string> data_;
    std::unordered_map<std::string_view, uint64_t> values_;

    friend class base_impl<exact_match>;
};

} // namespace ddwaf::matcher
