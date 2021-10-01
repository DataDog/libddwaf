// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#undef TESTING

#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <string>

#include "ddwaf.h"
#include <PWRet.hpp>

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

void PWRetManager::recordRuleMatch(const std::unique_ptr<IPWRuleProcessor>& processor, const MatchGatherer& gather)
{
    rapidjson::Value output, opNameValue, opValue, baValue, manifestKey;
    output.SetObject();

    std::string_view opName = processor->operatorName();
    opNameValue.SetString(opName.data(), static_cast<rapidjson::SizeType>(opName.size()));
    output.AddMember("operator", opNameValue, allocator);

    if (processor->hasStringRepresentation())
    {
        const std::string representation = processor->getStringRepresentation();
        opValue.SetString(representation.c_str(), static_cast<rapidjson::SizeType>(representation.size()), allocator);
        output.AddMember("operator_value", opValue, allocator);
    }

    if (!gather.dataSource.empty())
    {
        baValue.SetString(gather.dataSource.c_str(), static_cast<rapidjson::SizeType>(gather.dataSource.size()), allocator);
        output.AddMember("binding_accessor", baValue, allocator);
    }

    if (!gather.manifestKey.empty())
    {
        manifestKey.SetString(gather.manifestKey.c_str(), static_cast<rapidjson::SizeType>(gather.manifestKey.size()), allocator);
        output.AddMember("manifest_key", manifestKey, allocator);
    }

    if (!gather.keyPath.empty())
    {
        rapidjson::Value keyPathCopy;
        keyPathCopy.SetArray();

        for (const ddwaf_object& key : gather.keyPath)
        {
            rapidjson::Value jsonKey;
            if (key.type == DDWAF_OBJ_STRING)
                jsonKey.SetString(key.stringValue, static_cast<rapidjson::SizeType>(key.nbEntries), allocator);
            else
                jsonKey.SetUint64(key.uintValue);

            keyPathCopy.PushBack(jsonKey, allocator);
        }

        output.AddMember("key_path", keyPathCopy, allocator);
    }

    if (!gather.resolvedValue.empty())
    {
        rapidjson::Value resolvedValue;
        resolvedValue.SetString(gather.resolvedValue.c_str(), static_cast<rapidjson::SizeType>(gather.resolvedValue.size()), allocator);
        output.AddMember("resolved_value", resolvedValue, allocator);
    }

    if (!gather.matchedValue.empty())
    {
        rapidjson::Value matchStatus;
        matchStatus.SetString(gather.matchedValue.c_str(), static_cast<rapidjson::SizeType>(gather.matchedValue.size()), allocator);
        output.AddMember("match_status", matchStatus, allocator);
    }

    ruleCollector.PushBack(output, allocator);
}

void PWRetManager::commitResult(DDWAF_RET_CODE code, const std::string& flow)
{
    rapidjson::Value output, flowValue;

    output.SetObject();
    flowValue.SetString(flow.c_str(), static_cast<rapidjson::SizeType>(flow.size()), allocator);

    output.AddMember("ret_code", (int) code, allocator);
    output.AddMember("flow", flowValue, allocator);

    outputDocument.PushBack(output, allocator);
    recordResult(code);
}

rapidjson::Value PWRetManager::fetchRuleCollector()
{
    // This will actually move the content of the ruleCollector: We're now an empty shell
    return ruleCollector.GetArray();
}

void PWRetManager::removeResultFlow(const std::string& flow)
{
    rapidjson::SizeType lastIndex = outputDocument.GetArray().Size();
    while (lastIndex-- > 0)
    {
        const rapidjson::Value& obj = outputDocument.GetArray()[lastIndex];

        // If we're reporting an error, keep the report
        if (OBJ_HAS_KEY_AS_INT(obj, "ret_code") && obj["ret_code"].GetInt64() < 0)
        {
            break;
        }

        // If the flow is still the one we're deleting, pop the item
        else if (OBJ_HAS_KEY_AS_STRING(obj, "flow") && flow == obj["flow"].GetString())
        {
            outputDocument.GetArray().PopBack();
        }

        // If we're done with the flow, leave the function
        else
        {
            break;
        }
    }
}

void PWRetManager::reportMatch(DDWAF_RET_CODE code, const std::string& flow, const std::string& rule, const rapidjson::Value& filters)
{
    // We don't want to report matches caused by the cache
    rapidjson::Value output, flowValue, ruleValue;

    output.SetObject();
    flowValue.SetString(flow.c_str(), static_cast<rapidjson::SizeType>(flow.size())); // Safe without an allocator because the underlying buffer is long lived
    ruleValue.SetString(rule.c_str(), static_cast<rapidjson::SizeType>(rule.size()), allocator);

    output.AddMember("ret_code", (int) code, allocator);
    output.AddMember("flow", flowValue, allocator);
    output.AddMember("rule", ruleValue, allocator);

    if (filters.IsArray() && filters.GetArray().Size())
    {
        rapidjson::Value array;
        array.CopyFrom(filters, allocator);
        output.AddMember("filter", array, allocator);
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
