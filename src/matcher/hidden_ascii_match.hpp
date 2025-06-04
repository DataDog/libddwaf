// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "matcher/base.hpp"

namespace ddwaf::matcher {

class hidden_ascii_match : public base_impl<hidden_ascii_match> {
public:
    static constexpr std::string_view matcher_name = "hidden_ascii_match";
    static constexpr std::string_view negated_matcher_name = "!hidden_ascii_match";

    hidden_ascii_match() = default;
    ~hidden_ascii_match() override = default;
    hidden_ascii_match(const hidden_ascii_match &) = delete;
    hidden_ascii_match(hidden_ascii_match &&) noexcept = default;
    hidden_ascii_match &operator=(const hidden_ascii_match &) = delete;
    hidden_ascii_match &operator=(hidden_ascii_match &&) noexcept = default;

protected:
    [[nodiscard]] std::string_view to_string_impl() const { return ""; }
    static constexpr bool is_supported_type_impl(object_type type)
    {
        return type == object_type::string;
    }

    [[nodiscard]] static std::pair<bool, dynamic_string> match_impl(std::string_view pattern);

    friend class base_impl<hidden_ascii_match>;
};

} // namespace ddwaf::matcher
