// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <stdexcept>
#include <vector>

#include "exception.hpp"
#include "matcher/phrase_match.hpp"

namespace ddwaf::matcher {

namespace {
bool is_bounded_word(std::string_view pattern, std::size_t end)
{
    return (end + 1 >= pattern.size()) ||
           ((end + 1 < pattern.size()) && isboundary(pattern[end + 1]));
}

} // namespace

phrase_match::phrase_match(
    std::vector<const char *> pattern, std::vector<uint32_t> lengths, bool enforce_word_boundary)
    : enforce_word_boundary_(enforce_word_boundary)
{
    if (pattern.size() != lengths.size()) {
        throw std::invalid_argument("inconsistent pattern and lengths array size");
    }

    ac_t *ac_ = ac_create(pattern.data(), lengths.data(), pattern.size());
    if (ac_ == nullptr) {
        throw std::runtime_error("failed to instantiate ac handler");
    }

    ac = std::unique_ptr<ac_t, void (*)(void *)>(ac_, ac_free);
}

std::pair<bool, std::string> phrase_match::match_impl(std::string_view pattern) const
{
    ac_t *acStructure = ac.get();
    if (pattern.empty() || pattern.data() == nullptr || acStructure == nullptr) {
        return {false, {}};
    }

    auto u32_size = static_cast<uint32_t>(pattern.size());
    ac_result_t result;
    if (!enforce_word_boundary_) {
        result = ac_match(acStructure, pattern.data(), u32_size);
    } else {
        result = ac_match_longest_l(acStructure, pattern.data(), u32_size);
    }

    auto match_begin = static_cast<std::size_t>(result.match_begin);
    auto match_end = static_cast<std::size_t>(result.match_end);

    if (result.match_begin < 0 || result.match_end < 0 || match_begin >= match_end ||
        (enforce_word_boundary_ && !is_bounded_word(pattern, match_end))) {
        return {false, {}};
    }

    if (pattern.size() <= match_end) [[unlikely]] {
        return {true, {}};
    }

    return {true, std::string{pattern.substr(match_begin, (match_end - match_begin + 1))}};
}

} // namespace ddwaf::matcher
