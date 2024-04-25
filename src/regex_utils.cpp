// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "regex_utils.hpp"

namespace ddwaf {

std::unique_ptr<re2::RE2> regex_init(std::string_view pattern, bool case_sensitive)
{
    re2::RE2::Options options;
    options.set_log_errors(false);
    options.set_case_sensitive(case_sensitive);

    const re2::StringPiece pattern_ref(pattern.data(), pattern.size());
    auto regex = std::make_unique<re2::RE2>(pattern_ref, options);
    if (regex == nullptr) {
        throw std::runtime_error("invalid regular expression (" + std::string(pattern) + ")");
    }

    if (!regex->ok()) {
        throw std::runtime_error(
            "invalid regular expression (" + std::string(pattern) + "): " + regex->error_arg());
    }
    return regex;
}

std::unique_ptr<re2::RE2> regex_init_nothrow(std::string_view pattern, bool case_sensitive)
{
    re2::RE2::Options options;
    options.set_log_errors(false);
    options.set_case_sensitive(case_sensitive);

    const re2::StringPiece pattern_ref(pattern.data(), pattern.size());
    auto regex = std::make_unique<re2::RE2>(pattern_ref, options);
    if (regex == nullptr || !regex->ok()) {
        return nullptr;
    }
    return regex;
}

bool regex_match(re2::RE2 &regex, std::string_view subject, re2::RE2::Anchor anchor)
{
    const re2::StringPiece subject_ref(subject.data(), subject.size());
    return regex.Match(subject_ref, 0, subject_ref.size(), anchor, nullptr, 0);
}

} // namespace ddwaf
