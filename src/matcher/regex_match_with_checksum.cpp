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

#include "checksum/base.hpp"
#include "configuration/common/parser_exception.hpp"
#include "dynamic_string.hpp"
#include "matcher/regex_match_with_checksum.hpp"
#include "re2.h"

namespace ddwaf::matcher {

regex_match_with_checksum::regex_match_with_checksum(const std::string &regex_str,
    std::size_t minLength, bool case_sensitive, std::unique_ptr<base_checksum> &&algo)
    : min_length(minLength), algo_(std::move(algo))
{
    constexpr unsigned regex_max_mem = 512 * 1024;

    if (!algo_) {
        throw parsing_error("invalid checksum algorithm");
    }

    re2::RE2::Options options;
    options.set_max_mem(regex_max_mem);
    options.set_log_errors(false);
    options.set_case_sensitive(case_sensitive);

    regex = std::make_unique<re2::RE2>(regex_str, options);
    if (!regex->ok()) {
        throw parsing_error("invalid regular expression: " + regex->error_arg());
    }
}

std::pair<bool, dynamic_string> regex_match_with_checksum::match_impl(
    std::string_view pattern) const
{
    while (pattern.size() >= min_length) {
        std::string_view match;
        if (!regex->Match(pattern, 0, pattern.size(), RE2::UNANCHORED, &match, 1)) {
            break;
        }

        if (algo_->validate(match)) {
            return {true, match};
        }

        pattern.remove_prefix(match.data() - pattern.data() + match.size());
    }

    return {false, {}};
}

} // namespace ddwaf::matcher
