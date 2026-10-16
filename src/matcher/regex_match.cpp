// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

#include "configuration/common/parser_exception.hpp"
#include "dynamic_string.hpp"
#include "matcher/compiled_cache.hpp"
#include "matcher/regex_match.hpp"
#include "matcher/regex_prefilter.hpp"
#include "re2.h"

namespace ddwaf::matcher {

regex_match::regex_match(const std::string &regex_str, std::size_t minLength, bool case_sensitive)
    : min_length(minLength)
{
    regex = compile_regex(regex_str, case_sensitive);
    if (!regex->ok()) {
        throw parsing_error("invalid regular expression: " + regex->error_arg());
    }
}

const regex_prefilter *regex_match::build_prefilter() const
{
    // Prefilters are only built when rulesets are built, while get_prefilter
    // may be called concurrently by evaluations of other rulesets
    if (!prefilter_built_.load(std::memory_order_acquire)) {
        const std::scoped_lock lock{prefilter_mutex_};
        if (!prefilter_built_.load(std::memory_order_relaxed)) {
            prefilter_ = regex_prefilter::from_regex(*regex);
            prefilter_built_.store(true, std::memory_order_release);
        }
    }
    return prefilter_.get();
}

std::pair<bool, dynamic_string> regex_match::match_impl(std::string_view pattern) const
{
    if (pattern.size() < min_length || pattern.empty()) {
        return {false, {}};
    }

    std::string_view match;
    if (!regex->Match(pattern, 0, pattern.size(), RE2::UNANCHORED, &match, 1)) {
        return {false, {}};
    }

    return {true, match};
}

} // namespace ddwaf::matcher
