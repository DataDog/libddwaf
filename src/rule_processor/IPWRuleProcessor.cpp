// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <IPWRuleProcessor.h>

void MatchGatherer::clear()
{
    resolvedValue.clear();
    matchedValue.clear();
    keyPath.clear();
}

bool IPWRuleProcessor::doesMatch(const ddwaf_object* pattern, MatchGatherer& gatherer) const
{
    return performMatch(pattern->stringValue, (size_t) pattern->nbEntries, gatherer);
}

bool IPWRuleProcessor::doesMatchKey(const ddwaf_object* pattern, MatchGatherer& gatherer) const
{
    if (pattern->parameterName == nullptr)
        return false;

    return performMatch(pattern->parameterName, (size_t) pattern->parameterNameLength, gatherer);
}

bool IPWRuleProcessor::matchIfMissing() const
{
    // If we have no data but we're supposed to run, we can't be matching the operator's value
    //	That means that whether the operator match or not depend of whether it's supposed to
    //	If the operator "match" when not matching its value (i.e. !wantMatch), then it does match
    //		when no data is provided
    return runOnMissing && !wantMatch;
}

bool IPWRuleProcessor::matchAnyInput() const
{
    // If we have an empty container, do we want to "match"
    return matchAny;
}

uint64_t IPWRuleProcessor::expectedTypes() const
{
    return DDWAF_OBJ_STRING;
}

bool IPWRuleProcessor::hasStringRepresentation() const
{
    return false;
}

const std::string IPWRuleProcessor::getStringRepresentation() const
{
    return "(null)";
}
