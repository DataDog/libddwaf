// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.


#include <rule_processor/phrase_match.hpp>
#include <exception.hpp>
#include <stdexcept>
#include <vector>

namespace ddwaf::rule_processor
{

phrase_match::phrase_match(std::vector<const char*> pattern, std::vector<uint32_t> lengths)
{
    if (pattern.size() != lengths.size())
    {
        throw std::invalid_argument("inconsistent pattern and lengths array size");
    }

    ac_t* ac_ = ac_create(pattern.data(), lengths.data(), pattern.size());
    if (ac_ == nullptr)
    {
        throw std::runtime_error("failed to instantiate ac handler");
    }

    ac = std::unique_ptr<ac_t, void (*)(void*)>(ac_, ac_free);
}

std::optional<event::match> phrase_match::match(std::string_view str) const
{
    ac_t* acStructure = ac.get();
    if (str.empty() || acStructure == nullptr) {
        return {};
    }

    ac_result_t result = ac_match(acStructure, str.data(), static_cast<uint32_t>(str.size()));

    bool didMatch   = result.match_begin >= 0 && result.match_end >= 0 && result.match_begin < result.match_end;
    if (!didMatch) { return {}; }

    std::string matched_value;
    if (str.size() > (uint32_t)result.match_end) {
        matched_value = str.substr(result.match_begin, (result.match_end - result.match_begin + 1));
    }

    return event::match{std::string(str), std::move(matched_value), name(), to_string(), {}, {}};
}

}
