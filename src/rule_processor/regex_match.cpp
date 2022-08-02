// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule_processor/regex_match.hpp>
#include <exception.hpp>

namespace ddwaf::rule_processor
{

regex_match::regex_match(const std::string& regex_str, std::size_t minLength, bool caseSensitive):
    min_length(minLength)
{
    re2::RE2::Options options;
    options.set_max_mem(512 * 1024);
    options.set_log_errors(false);
    options.set_case_sensitive(caseSensitive);

    regex = std::make_unique<re2::RE2>(regex_str, options);

    if (!regex->ok())
    {
        throw parsing_error("invalid regular expression: " + regex->error_arg());
    }
}

bool regex_match::match(const char* str, size_t length, MatchGatherer& gatherer) const
{
    if (str == nullptr || !regex->ok() || length < min_length) {
        return false;
    }

    const re2::StringPiece ref(str, length);
    re2::StringPiece match[max_match_count];
    bool didMatch = regex->Match(ref,
                                 0,
                                 length,
                                 re2::RE2::UNANCHORED,
                                 match, 1);

    if (!didMatch) { return false; }

    gatherer.resolvedValue = std::string(str, length);
    gatherer.matchedValue = match[0].as_string();

    return true;
}

}
