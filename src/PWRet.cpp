// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#undef TESTING

#include "ddwaf.h"
#include <Clock.hpp>
#include <PWRet.hpp>
#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <string>

ddwaf_result returnErrorCode(DDWAF_RET_CODE code)
{
    ddwaf_result output;

    output.action           = code;
    output.data             = NULL;
    output.perfTotalRuntime = 0;
    output.perfData         = NULL;

    return output;
}

PWRetManager::PWRetManager(uint32_t slotsToSaveTimeFor, rapidjson::Document::AllocatorType& alloc) : allocator(alloc), roomInTimeStore(slotsToSaveTimeFor)
{
    outputDocument.SetArray();
    timeStore.resize(slotsToSaveTimeFor);
}

bool PWRetManager::shouldRecordTime() const
{
    return roomInTimeStore != 0;
}

void PWRetManager::recordResult(DDWAF_RET_CODE code)
{
    if (worstCode < code)
        worstCode = code;
}

void PWRetManager::recordTime(const std::string& ruleName, SQPowerWAF::monotonic_clock::duration _duration)
{
    // Check if this is a slow enough run to be worth storing
    const uint32_t duration = (uint32_t) std::min(_duration.count() / 1000, SQPowerWAF::monotonic_clock::duration::rep(UINT32_MAX));
    if (duration <= lowestTime || roomInTimeStore == 0)
        return;

    // If yes, store it
    timeStore[lowestTimeIndex] = std::make_pair(std::make_pair(ruleName.c_str(), ruleName.size()), duration);
    lowestTime                 = duration;

    // Find the next quickest rule for eviction
    for (uint32_t i = 0; i < roomInTimeStore; ++i)
    {
        if (timeStore[i].second < lowestTime)
        {
            lowestTime      = timeStore[i].second;
            lowestTimeIndex = i;
        }
    }
}

void PWRetManager::startRule()
{
    ruleCollector = rapidjson::Value();
    ruleCollector.SetArray();
}

rapidjson::GenericStringRef<char> ref_from_string(std::string_view sv)
{
    if (sv.empty())
    {
        return { "", 0 };
    }
    return { sv.data(), static_cast<rapidjson::SizeType>(sv.size()) };
}

void PWRetManager::recordRuleMatch(const std::unique_ptr<IPWRuleProcessor>& processor, const MatchGatherer& gather)
{
    rapidjson::Value output;
    output.SetObject();

    output.AddMember("operator", ref_from_string(processor->operatorName()), allocator);

    if (processor->hasStringRepresentation())
    {
        output.AddMember("operator_value", processor->getStringRepresentation(), allocator);
    }
    else
    {
        output.AddMember("operator_value", "", allocator);
    }

    rapidjson::Value parameters, param, key_path;
    parameters.SetArray();

    param.SetObject();
    param.AddMember("address", gather.dataSource, allocator);
    key_path.SetArray();
    for (const ddwaf_object& key : gather.keyPath)
    {
        rapidjson::Value jsonKey;
        if (key.type == DDWAF_OBJ_STRING)
        {
            if (key.stringValue == nullptr || key.nbEntries == 0) {
                // This shouldn't happen
                continue;
            }
            jsonKey.SetString(key.stringValue, static_cast<rapidjson::SizeType>(key.nbEntries), allocator);
        }
        else
        {
            jsonKey.SetUint64(key.uintValue);
        }
        key_path.PushBack(jsonKey, allocator);
    }
    param.AddMember("key_path", key_path, allocator);
    param.AddMember("value", gather.resolvedValue, allocator);
    rapidjson::Value highlight, matchedValue;
    highlight.SetArray();
    if (!gather.matchedValue.empty())
    {
        matchedValue.SetString(gather.matchedValue, allocator);
        highlight.PushBack(matchedValue, allocator);
    }
    param.AddMember("highlight", highlight, allocator);
    parameters.PushBack(param, allocator);
    output.AddMember("parameters", parameters, allocator);

    ruleCollector.PushBack(output, allocator);
}

rapidjson::Value PWRetManager::fetchRuleCollector()
{
    // This will actually move the content of the ruleCollector: We're now an empty shell
    return ruleCollector.GetArray();
}

void PWRetManager::reportMatch(const std::string& id,
                               const std::string& type, const std::string& category,
                               const std::string& name, const rapidjson::Value& filters)
{
    // We don't want to report matches caused by the cache
    rapidjson::Value output, ruleValue, tagsValue;

    output.SetObject();

    tagsValue.SetObject();
    tagsValue.AddMember("type", type, allocator);
    tagsValue.AddMember("category", category, allocator);

    ruleValue.SetObject();
    ruleValue.AddMember("id", id, allocator);
    ruleValue.AddMember("name", name, allocator);
    ruleValue.AddMember("tags", tagsValue, allocator);

    output.AddMember("rule", ruleValue, allocator);

    if (filters.IsArray() && filters.GetArray().Size())
    {
        rapidjson::Value array;
        array.CopyFrom(filters, allocator);
        output.AddMember("rule_matches", array, allocator);
    }

    outputDocument.PushBack(output, allocator);
}

void PWRetManager::synthetizeTimeSlots(rapidjson::Document& timeSlotDocument) const
{
    //
    // Expected format is:
    //
    //	{
    //		"topRuleRuntime": [
    //		   ["rule_123456", 150],
    //		   ["rule_789123", 140],
    //		   ["rule_456789", 100]
    //	   ]
    //	}
    //

    timeSlotDocument.SetObject();

    // Should we try to sort them?
    rapidjson::Value recordCollector;
    recordCollector.SetArray();

    for (const auto& timeRecord : timeStore)
    {
        // We didn't fill the whole store
        if (timeRecord.second == 0)
            break;

        // Populate the entry
        rapidjson::Value entry;
        entry.SetArray();

        {
            rapidjson::Value ruleName;
            ruleName.SetString(timeRecord.first.first, rapidjson::SizeType(timeRecord.first.second));
            entry.PushBack(ruleName, timeSlotDocument.GetAllocator());
        }

        {
            rapidjson::Value timeSpent;
            timeSpent.SetUint(timeRecord.second);
            entry.PushBack(timeSpent, timeSlotDocument.GetAllocator());
        }

        recordCollector.PushBack(entry, timeSlotDocument.GetAllocator());
    }

    timeSlotDocument.AddMember("topRuleRuntime", recordCollector, timeSlotDocument.GetAllocator());
}

ddwaf_result PWRetManager::synthetize() const
{
    ddwaf_result output = returnErrorCode(worstCode);

    if (outputDocument.GetArray().Size() > 0)
    {
        rapidjson::StringBuffer buffer;
        buffer.Clear();

        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        if (outputDocument.Accept(writer))
            output.data = strdup(buffer.GetString());
    }

    // If we wrote anything, either the lowest value, or the index of the lowest value has to change (their both 0 by default)
    if (shouldRecordTime() && (lowestTime != 0 || lowestTimeIndex != 0))
    {
        rapidjson::StringBuffer buffer;
        buffer.Clear();

        rapidjson::Document timeSlotCollector;
        synthetizeTimeSlots(timeSlotCollector);

        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        if (timeSlotCollector.Accept(writer))
            output.perfData = strdup(buffer.GetString());
    }

    return output;
}

extern "C"
{
    void ddwaf_result_free(ddwaf_result* result)
    {
        free(const_cast<char*>(result->data));
        free(const_cast<char*>(result->perfData));
    }
}
