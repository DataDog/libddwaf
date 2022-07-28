// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule_processor/libinjection.hpp>
#include <libinjection.h>
#include <utils.h>

namespace ddwaf::rule_processor
{

bool is_sqli::match(const char* pattern, size_t length, MatchGatherer& gatherer) const
{
    //The mandated length is 8
    char fingerprint[16]        = { 0 };

    if (!libinjection_sqli(pattern, length, fingerprint)) {
        return false;
    }

    gatherer.resolvedValue = std::string(pattern, length);
    gatherer.matchedValue = std::string(fingerprint);

    return true;
}

bool is_xss::match(const char* pattern, size_t length, MatchGatherer& gatherer) const
{
    if (!libinjection_xss(pattern, length)) {
        return false;
    }

    gatherer.resolvedValue = std::string(pattern, length);

    return true;
}

}
