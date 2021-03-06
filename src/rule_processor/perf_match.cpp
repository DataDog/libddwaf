// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <ac.h>

#include <IPWRuleProcessor.h>
#include <exception.hpp>
#include <stdexcept>
#include <vector>

PerfMatch::PerfMatch(std::vector<const char*> pattern, std::vector<uint32_t> lengths) : IPWRuleProcessor()
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

bool PerfMatch::performMatch(const char* patternValue, size_t patternLength, MatchGatherer& gatherer) const
{
    ac_t* acStructure = ac.get();
    if (patternValue == NULL || patternLength == 0 || acStructure == nullptr)
        return false;

    ac_result_t result = ac_match(acStructure, patternValue, (uint32_t) patternLength);

    bool didMatch   = result.match_begin >= 0 && result.match_end >= 0 && result.match_begin < result.match_end;
    bool didSucceed = didMatch == wantMatch;

    if (didSucceed)
    {
        gatherer.resolvedValue = std::string(patternValue, patternLength);
        if (didMatch && patternLength > (uint32_t) result.match_end)
        {
            gatherer.matchedValue = std::string(&patternValue[result.match_begin], (uint32_t)(result.match_end - result.match_begin + 1));
        }
    }

    return didSucceed;
}
