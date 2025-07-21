// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <re2/re2.h>

#include "matcher/base.hpp"

namespace ddwaf::matcher {

enum class check_digit_algorithm : uint8_t { luhn };

inline check_digit_algorithm cda_from_string(std::string_view str)
{
    if (str == "luhn") {
        return check_digit_algorithm::luhn;
    }

    throw std::invalid_argument("unknown check digit algorithm");
}

// Exposed for testing
bool is_luhn_identifier(std::string_view str);

class check_digit_match : public base_impl<check_digit_match> {
public:
    static constexpr std::string_view matcher_name = "check_digit_match";
    static constexpr std::string_view negated_matcher_name = "!check_digit_match";

    check_digit_match(check_digit_algorithm cda, const std::string &regex_str,
        std::size_t minLength, bool case_sensitive);
    ~check_digit_match() override = default;
    check_digit_match(const check_digit_match &) = delete;
    check_digit_match(check_digit_match &&) noexcept = default;
    check_digit_match &operator=(const check_digit_match &) = delete;
    check_digit_match &operator=(check_digit_match &&) noexcept = default;

protected:
    [[nodiscard]] std::string_view to_string_impl() const { return regex->pattern(); }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        return type == DDWAF_OBJ_STRING;
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(std::string_view pattern) const;

    check_digit_algorithm cda_;
    std::unique_ptr<re2::RE2> regex{nullptr};
    std::size_t min_length;

    friend class base_impl<check_digit_match>;
};

} // namespace ddwaf::matcher
