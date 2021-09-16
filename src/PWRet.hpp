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

#include <PWRule.hpp>
#include <ddwaf.h>
#include <utils.h>

class PWRetManager
{
    rapidjson::Document outputDocument;
    rapidjson::Document::AllocatorType& allocator;
    rapidjson::Value ruleCollector;

    DDWAF_RET_CODE worstCode = DDWAF_GOOD;

    // Time reporting
    const uint32_t roomInTimeStore;
    uint32_t lowestTime      = 0;
    uint32_t lowestTimeIndex = 0;
    std::vector<std::pair<std::pair<const char*, size_t>, uint32_t>> timeStore;

    void synthetizeTimeSlots(rapidjson::Document& timeSlotCollector) const;

public:
    PWRetManager(uint32_t slotsToSaveTimeFor, rapidjson::Document::AllocatorType& allocator);

    bool shouldRecordTime() const;

    void recordResult(DDWAF_RET_CODE code);
    void recordTime(const std::string& ruleName, SQPowerWAF::monotonic_clock::duration duration);

    void startRule();
    void recordRuleMatch(const std::unique_ptr<IPWRuleProcessor>& processor, const MatchGatherer& gather);

    void returnCode(DDWAF_RET_CODE code);
    void commitResult(DDWAF_RET_CODE code, const std::string& flow);
    void reportMatch(DDWAF_RET_CODE code, const std::string& flow, const std::string& rule, const rapidjson::Value& filters);

    rapidjson::Value fetchRuleCollector();

    void removeResultFlow(const std::string& flow);

    ddwaf_result synthetize() const;

#ifdef TESTING
    FRIEND_TEST(TestPWProcessor, TestCache);
    FRIEND_TEST(TestPWProcessor, TestBudget);
#endif
};

extern ddwaf_result returnErrorCode(DDWAF_RET_CODE code);

#endif /* PWRet_hpp */
