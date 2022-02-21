// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWProcessor_hpp
#define PWProcessor_hpp

#include <rapidjson/document.h>
#include <string>
#include <unordered_map>

struct PWProcessor;

#include <Clock.hpp>
#include <PWRet.hpp>
#include <PWRetriever.hpp>
#include <rule.hpp>

struct PWProcessor
{
    rapidjson::Document document;
    PWRetriever& parameters;
    const ddwaf::rule_map& rules;

    SQPowerWAF::monotonic_clock::time_point deadline;

    std::unordered_map<std::string, ddwaf::condition::status> ranCache;
    std::unordered_map<std::string, rapidjson::Value> matchCache;

    ddwaf::condition::status hasCacheHit(const std::string& ruleID) const;
    bool shouldIgnoreCacheHit(const std::vector<ddwaf::condition>& rules) const;

public:
    PWProcessor(PWRetriever& input, const ddwaf::rule_map& rules);
    void startNewRun(const SQPowerWAF::monotonic_clock::time_point& _deadline);
    void runFlow(const std::string& name, const std::vector<std::string>& flow, PWRetManager& manager);

    bool isFirstRun() const;
    rapidjson::Document::AllocatorType& getGlobalAllocator();
};

#endif /* PWProcessor_hpp */
