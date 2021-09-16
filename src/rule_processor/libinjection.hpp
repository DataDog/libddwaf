// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef libinjection_h
#define libinjection_h

#include <libinjection.h>

class LibInjectionSQL : public IPWRuleProcessor
{
    bool performMatch(const char* pattern, size_t length, MatchGatherer& gatherer) const override;

public:
    using IPWRuleProcessor::IPWRuleProcessor;
    bool buildProcessor(const rapidjson::Value&, bool) override;
};

class LibInjectionXSS : public IPWRuleProcessor
{
    bool performMatch(const char* pattern, size_t length, MatchGatherer& gatherer) const override;

public:
    using IPWRuleProcessor::IPWRuleProcessor;
    bool buildProcessor(const rapidjson::Value&, bool) override;
};

#endif /* libinjection_h */
