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
public:
    using IPWRuleProcessor::IPWRuleProcessor;
    LibInjectionSQL() = default;
    std::string_view operatorName() const override { return name; }
    bool match(const char* pattern, size_t length, MatchGatherer& gatherer) const override;

protected:
    static constexpr std::string_view name { "is_sqli" };
};

class LibInjectionXSS : public IPWRuleProcessor
{
public:
    using IPWRuleProcessor::IPWRuleProcessor;
    LibInjectionXSS() = default;
    std::string_view operatorName() const override { return name; }

    bool match(const char* pattern, size_t length, MatchGatherer& gatherer) const override;

protected:
    static constexpr std::string_view name { "is_xss" };
};

#endif /* libinjection_h */
