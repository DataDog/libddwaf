// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef IPWRuleProcessor_h
#define IPWRuleProcessor_h

#include <string>
#include <vector>

#include <ddwaf.h>
#include <string_view>
#include <utils.h>

typedef enum
{
    NONE           = 0,
    NEGATE         = 1 << 0,
    RUN_ON_NO_DATA = 1 << 1
} OperatorCommand;

struct MatchGatherer
{
    std::string resolvedValue;
    std::string matchedValue;
    std::vector<std::pair<uint8_t, std::string>> submatches;
    const std::vector<uint8_t>& submatchToGather;
    std::vector<ddwaf_object> keyPath;
    std::string dataSource;
    std::string manifestKey;

    MatchGatherer(const std::vector<uint8_t>& matchToGather);

    void clear();
};

class IPWRuleProcessor
{
protected:
    bool wantMatch { true };
    bool runOnMissing { false };
    bool matchAny { false };

    virtual bool performMatch(const char* str, size_t length, MatchGatherer& gatherer) const = 0;

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
    virtual std::string_view operatorName() const = 0;
};

#define OP_REGEX "@rx"
#define OP_EQ "@eq"
#define OP_GT "@gt"
#define OP_GE "@ge"
#define OP_LT "@lt"
#define OP_LE "@le"
#define OP_SQL "@detectSQLi"
#define OP_XSS "@detectXSS"
#define OP_BEGIN "@beginsWith"
#define OP_CONT "@contains"
#define OP_END "@endsWith"
#define OP_PM "@pm"
#define OP_EXIST "@exist"
#define OP_IPM "@ipMatch"

#include "libinjection.hpp"
#include "perf_match.hpp"
#include "re2.hpp"

#endif /* IPWRuleProcessor_h */
