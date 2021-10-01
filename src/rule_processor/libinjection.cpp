// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <IPWRuleProcessor.h>

#include <libinjection.h>
#include <utils.h>

bool LibInjectionSQL::performMatch(const char* pattern, size_t length, MatchGatherer& gatherer) const
{
    //The mandated length is 8
    char fingerprint[16]        = { 0 };
    const size_t computedLength = findStringCutoff(pattern, length);
    bool didMatch               = libinjection_sqli(pattern, computedLength, fingerprint) == 1;
    bool output                 = didMatch == wantMatch;

    if (output)
    {
        gatherer.resolvedValue = std::string(pattern, computedLength);
        if (didMatch)
        {
            gatherer.matchedValue = std::string(fingerprint);
        }
    }

    return output;
}

bool LibInjectionXSS::performMatch(const char* pattern, size_t length, MatchGatherer& gatherer) const
{
    const size_t computedLength = findStringCutoff(pattern, length);
    bool didMatch               = libinjection_xss(pattern, computedLength) == 1;
    bool output                 = didMatch == wantMatch;

    if (output)
        gatherer.resolvedValue = std::string(pattern, computedLength);

    return output;
}
