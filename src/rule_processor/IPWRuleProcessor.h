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

    void clear();
};

class IPWRuleProcessor
{
public:
    IPWRuleProcessor()          = default;
    virtual ~IPWRuleProcessor() = default;

    virtual bool doesMatch(const ddwaf_object* pattern, MatchGatherer& gatherer) const;
    virtual bool doesMatchKey(const ddwaf_object* pattern, MatchGatherer& gatherer) const;
    bool matchIfMissing() const;
    bool matchAnyInput() const;
    virtual uint64_t expectedTypes() const;
    virtual bool hasStringRepresentation() const;
    virtual const std::string getStringRepresentation() const;
    /* The return value of this function should outlive the function scope,
     * for example, through a constexpr class static string_view initialised
     * with a literal. */
    virtual std::string_view operatorName() const = 0;

protected:
    bool wantMatch { true };
    bool runOnMissing { false };
    bool matchAny { false };

    virtual bool performMatch(const char* str, size_t length, MatchGatherer& gatherer) const = 0;


};

#include "libinjection.hpp"
#include "perf_match.hpp"
#include "re2.hpp"
