// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#undef TESTING

#include "ddwaf.h"
#include <PWRet.hpp>
#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <string>

PWRetManager::PWRetManager(rapidjson::Document::AllocatorType& alloc, const std::shared_ptr<re2::RE2>& sensitiveRegex) : allocator(alloc), sensitiveRegex(sensitiveRegex)
{
    outputDocument.SetArray();
}

void PWRetManager::startRule()
{
    ruleCollector = rapidjson::Value();
    ruleCollector.SetArray();
}

void PWRetManager::recordRuleMatch(const std::unique_ptr<IPWRuleProcessor>& processor, const MatchGatherer& gather)
{
    rapidjson::Value output;
    output.SetObject();

    auto op = processor->operatorName();
    output.AddMember("operator",
                     rapidjson::GenericStringRef<char>(op.data(),
                                                       static_cast<rapidjson::SizeType>(op.size())),
                     allocator);

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
            if (key.stringValue == nullptr || key.nbEntries == 0)
            {
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

    // This field is required by the obfuscator and shouldn't be renamed
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

DDWAF_RET_CODE PWRetManager::synthetize(ddwaf_result& output) const
{
    output = { 0 };
    output.timeout = timeout;

    if (outputDocument.GetArray().Size() > 0)
    {
        rapidjson::StringBuffer buffer;
        buffer.Clear();

        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        if (outputDocument.Accept(writer))
            output.data = strdup(buffer.GetString());
    }

    return worstCode;
}

extern "C"
{
    void ddwaf_result_free(ddwaf_result* result)
    {
        free(const_cast<char*>(result->data));
        *result = { 0 };
    }
}
