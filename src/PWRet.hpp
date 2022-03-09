// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWRet_hpp
#define PWRet_hpp

#include <string>

#include <rapidjson/document.h>

class PWRetManager;

#include <IPWRuleProcessor.h>
#include <clock.hpp>
#include <ddwaf.h>
#include <memory>
#include <utils.h>

class PWRetManager
{
    rapidjson::Document outputDocument;
    rapidjson::Document::AllocatorType& allocator;
    rapidjson::Value ruleCollector;

    DDWAF_RET_CODE worstCode { DDWAF_GOOD };
    bool timeout { false };

public:
    PWRetManager(rapidjson::Document::AllocatorType& allocator);

    DDWAF_RET_CODE getResult() const { return worstCode; }

    void recordResult(DDWAF_RET_CODE code)
    {
        if (worstCode < code)
        {
            worstCode = code;
        }
    }

    void recordTimeout()
    {
        timeout = true;
    }

    void startRule();
    void recordRuleMatch(const std::unique_ptr<IPWRuleProcessor>& processor, const MatchGatherer& gather);

    void reportMatch(const std::string& id,
                     const std::string& type, const std::string& category,
                     const std::string& name, const rapidjson::Value& filters);

    rapidjson::Value fetchRuleCollector();

    void removeResultFlow(const std::string& flow);

    DDWAF_RET_CODE synthetize(ddwaf_result& output) const;

#ifdef TESTING
    FRIEND_TEST(TestPWProcessor, TestCache);
    FRIEND_TEST(TestPWProcessor, TestBudget);
#endif
};

#endif /* PWRet_hpp */
