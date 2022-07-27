// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <vector>

#include <ddwaf.h>
#include <string_view>
#include <utils.h>

struct MatchGatherer
{
    std::string resolvedValue;
    std::string matchedValue;
    std::vector<std::string> keyPath;
    std::string dataSource;

    MatchGatherer() = default;

    void clear() {
        resolvedValue.clear();
        matchedValue.clear();
        keyPath.clear();
        dataSource.clear();
    }
};

class IPWRuleProcessor
{
public:
    IPWRuleProcessor()          = default;
    virtual ~IPWRuleProcessor() = default;

    virtual bool match(const char* str, size_t length, MatchGatherer& gatherer) const = 0;

    virtual bool match_object(const ddwaf_object *obj, MatchGatherer &gatherer) const {
        return match(obj->stringValue, obj->nbEntries, gatherer);
    }

    virtual const std::string getStringRepresentation() const { return {}; }

    /* The return value of this function should outlive the function scope,
     * for example, through a constexpr class static string_view initialised
     * with a literal. */
    virtual std::string_view operatorName() const = 0;
};

#include "libinjection.hpp"
#include "perf_match.hpp"
#include "re2.hpp"
#include "ip_match.hpp"
