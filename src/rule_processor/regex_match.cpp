// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <exception.hpp>
#include <rule_processor/regex_match.hpp>

namespace ddwaf::rule_processor {

regex_match::regex_match(const std::string &regex_str, std::size_t minLength, bool case_sensitive)
    : min_length(minLength)
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

std::optional<event::match> regex_match::do_match(std::string_view pattern, allocator alloc) const
{
    if (pattern.data() == nullptr || !regex->ok() || pattern.size() < min_length) {
        return std::nullopt;
    }

    const re2::StringPiece ref(pattern.data(), pattern.size());
    std::array<re2::StringPiece, max_match_count> match;
    bool didMatch = regex->Match(ref, 0, pattern.size(), re2::RE2::UNANCHORED, match.data(), 1);

    if (!didMatch) {
        return std::nullopt;
    }

    return make_event(pattern, {match[0].data(), match[0].size()}, alloc);
}

} // namespace ddwaf::rule_processor
