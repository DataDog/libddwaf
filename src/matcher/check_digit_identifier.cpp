// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "configuration/common/parser_exception.hpp"
#include "dynamic_string.hpp"
#include "matcher/check_digit_identifier.hpp"
#include "re2.h"
#include "utils.hpp"

namespace ddwaf::matcher {

namespace {

bool eval_cda(check_digit_algorithm cda, std::string_view str)
{
    if (cda == check_digit_algorithm::luhn) {
        return is_luhn_identifier(str);
    }

    return false;
}

} // namespace

bool is_luhn_identifier(std::string_view str)
{
    unsigned check_digit = 0;
    std::size_t i = str.size();
    for (; i > 0; --i) {
        auto c = str[i - 1];
        if (!ddwaf::isdigit(c)) {
            continue;
        }

        check_digit = (c - '0');
        break;
    }

    unsigned total = 0;
    unsigned count = 0;
    for (i -= 1; i > 0; --i) {
        auto c = str[i - 1];
        if (!ddwaf::isdigit(c)) {
            continue;
        }

        unsigned num = c - '0';
        if ((count++ & 0x01) == 0) {
            num = (2 * num) / 10 + (2 * num) % 10;
        }
        total += num;
    }

    auto computed_digit = ((10 - (total % 10)) % 10);

    return computed_digit == check_digit;
}

check_digit_identifier::check_digit_identifier(check_digit_algorithm cda,
    const std::string &regex_str, std::size_t minLength, bool case_sensitive)
    : cda_(cda), min_length(minLength)
{
    constexpr unsigned regex_max_mem = 512 * 1024;

    re2::RE2::Options options;
    options.set_max_mem(regex_max_mem);
    options.set_log_errors(false);
    options.set_case_sensitive(case_sensitive);

    regex = std::make_unique<re2::RE2>(regex_str, options);

    if (!regex->ok()) {
        throw parsing_error("invalid regular expression: " + regex->error_arg());
    }
}

std::pair<bool, dynamic_string> check_digit_identifier::match_impl(std::string_view pattern) const
{
    if (pattern.data() == nullptr || !regex->ok() || pattern.size() < min_length) {
        return {false, {}};
    }

    std::string_view match;
    const bool res = regex->Match(pattern, 0, pattern.size(), re2::RE2::UNANCHORED, &match, 1);

    if (!res || !eval_cda(cda_, match)) {
        return {false, {}};
    }

    return {true, match};
}

} // namespace ddwaf::matcher
