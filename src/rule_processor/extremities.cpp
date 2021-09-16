// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <IPWRuleProcessor.h>

bool ExtremitiesMatch::performMatch(const char* pattern, size_t length, MatchGatherer& gatherer) const
{
    bool didMatch = matchString(pattern, length);
    bool output   = didMatch == wantMatch;

    if (output)
    {
        gatherer.resolvedValue = std::string(pattern, length);
        if (didMatch)
            gatherer.matchedValue = value;
    }

    return output;
}

bool ExtremitiesMatch::buildProcessor(const rapidjson::Value& _value, bool)
{
    if (!_value.IsString())
        return false;

    value = _value.GetString();
    return !value.empty();
}

bool ExtremitiesMatch::hasStringRepresentation() const
{
    return true;
}

const std::string ExtremitiesMatch::getStringRepresentation() const
{
    return value;
}

bool BeginsWith::matchString(const char* pattern, size_t patternLength) const
{
    const size_t length = value.length();
    if (patternLength < length)
        return false;

    return memcmp(pattern, value.c_str(), length) == 0;
}

bool Contains::matchString(const char* pattern, size_t patternLength) const
{
    const size_t length = value.length();
    if (patternLength < length)
        return false;

    const char* valueStr  = value.c_str();
    const size_t maxStart = patternLength - length;
    for (size_t pos = 0; pos <= maxStart; ++pos)
    {
        //If the first character match, we call memcmp on the rest of the string
        if (pattern[pos] == valueStr[0] && memcmp(&pattern[pos], valueStr, length) == 0)
            return true;
    }

    return false;
}

bool EndsWith::matchString(const char* pattern, size_t patternLength) const
{
    const size_t length = value.length();
    if (patternLength < length)
        return false;

    const size_t baseIndex = patternLength - length;

    return memcmp(&pattern[baseIndex], value.c_str(), length) == 0;
}
