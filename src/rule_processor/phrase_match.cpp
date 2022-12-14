// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <rule_processor/phrase_match.hpp>
#include <stdexcept>
#include <vector>

namespace ddwaf::rule_processor {

phrase_match::phrase_match(std::vector<const char *> pattern, std::vector<uint32_t> lengths)
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

std::optional<event::match> phrase_match::match(std::string_view pattern) const
{
    ac_t *acStructure = ac.get();
    if (pattern.empty() || pattern.data() == nullptr || acStructure == nullptr) {
        return std::nullopt;
    }

    ac_result_t result =
        ac_match(acStructure, pattern.data(), static_cast<uint32_t>(pattern.size()));

    bool didMatch =
        result.match_begin >= 0 && result.match_end >= 0 && result.match_begin < result.match_end;
    if (!didMatch) {
        return std::nullopt;
    }

    std::string_view matched_value;
    if (pattern.size() > (uint32_t)result.match_end) {
        matched_value =
            pattern.substr(result.match_begin, (result.match_end - result.match_begin + 1));
    }

    return make_event(pattern, matched_value);
}

} // namespace ddwaf::rule_processor
