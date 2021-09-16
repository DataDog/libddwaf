// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "IPWRuleProcessor.h"

bool Exist::performMatch(const char*, size_t, MatchGatherer&) const
{
    return true;
}

bool Exist::buildProcessor(const rapidjson::Value&, bool)
{
    runOnMissing = true;
    matchAny     = wantMatch;
    return true;
}

bool Exist::doesMatch(const ddwaf_object* pattern, MatchGatherer& gatherer) const
{
    if (wantMatch && pattern->type == DDWAF_OBJ_STRING)
    {
        gatherer.resolvedValue = std::string(pattern->stringValue, (size_t) pattern->nbEntries);
    }

    return wantMatch;
}

bool Exist::doesMatchKey(const ddwaf_object* pattern, MatchGatherer& gatherer) const
{
    if (wantMatch && pattern->parameterName != NULL)
    {
        gatherer.resolvedValue = std::string(pattern->parameterName, (size_t) pattern->parameterNameLength);
    }

    return wantMatch;
}

uint64_t Exist::expectedTypes() const
{
    return PWI_DATA_TYPES | PWI_CONTAINER_TYPES;
}
