// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string_view>
#include <unordered_map>
#include <vector>

#include "matcher/base.hpp"

namespace ddwaf::matcher {

class exact_match : public base_impl<exact_match> {
public:
    using data_type = std::vector<std::pair<std::string, uint64_t>>;

    static constexpr std::string_view matcher_name = "exact_match";
    static constexpr std::string_view negated_matcher_name = "!exact_match";

    exact_match() = default;
    explicit exact_match(std::vector<std::string> &&data);
    explicit exact_match(const data_type &data);
    ~exact_match() override = default;
    exact_match(const exact_match &) = default;
    exact_match(exact_match &&) = default;
    exact_match &operator=(const exact_match &) = default;
    exact_match &operator=(exact_match &&) = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        return type == DDWAF_OBJ_STRING;
    }

    [[nodiscard]] std::pair<bool, std::string> match_impl(std::string_view str) const;

    std::vector<std::string> data_;
    std::unordered_map<std::string_view, uint64_t> values_;

    friend class base_impl<exact_match>;
};

} // namespace ddwaf::matcher
