// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <IPWRuleProcessor.h>
#include <exception.hpp>
#include <utils.h>

using namespace ddwaf;

RE2Manager::RE2Manager(const std::string& regex_str, std::size_t minLength, bool caseSensitive):
    IPWRuleProcessor(), min_length(minLength)
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

    groupsToCatch = (uint8_t) std::min(regex->NumberOfCapturingGroups() + 1, MAX_MATCH_COUNT);
}

bool RE2Manager::performMatch(const char* str, size_t length, MatchGatherer& gatherer) const
{
    if (!regex->ok() || length < min_length) {
        return false;
    }

    const size_t computedLength = findStringCutoff(str, length);
    const re2::StringPiece ref(str, computedLength);
    re2::StringPiece match[MAX_MATCH_COUNT];
    bool didMatch = regex->Match(ref,
                                 0,
                                 computedLength,
                                 re2::RE2::UNANCHORED,
                                 match,
                                 gatherer.submatchToGather.empty() ? 1 : groupsToCatch);

    //Copy on match
    bool output = didMatch == wantMatch;

    if (output)
    {
        gatherer.resolvedValue = std::string(str, computedLength);
        if (didMatch)
        {
            gatherer.matchedValue = match[0].as_string();
            if (!gatherer.submatchToGather.empty())
            {
                gatherer.submatches.clear();
                for (const uint8_t subMatch : gatherer.submatchToGather)
                {
                    if (subMatch > groupsToCatch || match[subMatch].empty())
                    {
                        break;
                    }

                    gatherer.submatches.emplace_back(subMatch, match[subMatch].as_string());
                }
            }
        }
    }

    return output;
}

bool RE2Manager::hasStringRepresentation() const
{
    return true;
}

const std::string RE2Manager::getStringRepresentation() const
{
    return regex->pattern();
}
