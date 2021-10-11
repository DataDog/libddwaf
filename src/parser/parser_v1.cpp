// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWManifest.h>
#include <PWRetriever.hpp>
#include <PWRuleManager.hpp>
#include <exception.hpp>
#include <log.hpp>
#include <parameter.hpp>
#include <parser/common.hpp>
#include <string>
#include <unordered_map>
#include <vector>

using namespace ddwaf;
using namespace ddwaf::parser;

namespace
{

PWRule parseCondition(parameter::map& rule, PWManifest& manifest,
                      std::vector<PW_TRANSFORM_ID>& transformers)
{
    auto operation = at<std::string_view>(rule, "operation");
    auto params    = at<parameter::map>(rule, "parameters");

    parameter::map options;
    std::unique_ptr<IPWRuleProcessor> processor;
    if (operation == "phrase_match")
    {
        auto list = at<parameter::vector>(params, "list");

        std::vector<const char*> patterns;
        std::vector<uint32_t> lengths;

        patterns.reserve(list.size());
        lengths.reserve(list.size());

        for (auto& pattern : list)
        {
            if (pattern.type != DDWAF_OBJ_STRING)
            {
                throw parsing_error("phrase_match list item not a string");
            }

            patterns.push_back(pattern.stringValue);
            lengths.push_back(pattern.nbEntries);
        }

        processor = std::make_unique<PerfMatch>(patterns, lengths);
    }
    else if (operation == "match_regex")
    {
        auto regex = at<std::string>(params, "regex");
        options    = at<parameter::map>(params, "options", options);

        bool case_sensitive = false;
        if (options.find("case_sensitive") != options.end())
        {
            std::string case_opt = options["case_sensitive"];
            std::transform(case_opt.begin(), case_opt.end(), case_opt.begin(), ::tolower);
            if (case_opt == "true")
            {
                case_sensitive = true;
            }
        }
        // TODO support min length
        processor = std::make_unique<RE2Manager>(regex, case_sensitive);
    }
    else if (operation == "is_xss")
    {
        processor = std::make_unique<LibInjectionXSS>();
    }
    else if (operation == "is_sqli")
    {
        processor = std::make_unique<LibInjectionSQL>();
    }
    else
    {
        throw parsing_error("unknown processor: " + std::string(operation));
    }

    std::vector<PWManifest::ARG_ID> targets;
    auto inputs = at<parameter::vector>(params, "inputs");
    for (std::string input : inputs)
    {
        if (input.empty())
        {
            throw parsing_error("empty address");
        }

        PWManifest::ARG_ID id;
        if (manifest.hasTarget(input))
        {
            id = manifest.getTargetArgID(input);
        }
        else
        {
            PWManifest::ArgDetails details;
            size_t pos = input.find(':', 0);
            if (pos == std::string::npos || pos + 1 >= input.size())
            {
                details.inheritFrom = input;
            }
            else
            {
                details.inheritFrom = input.substr(0, pos);
                details.keyPaths.emplace(input.substr(pos + 1, input.size()));
            }

            id = manifest.insert(input, std::move(details));
        }
        targets.push_back(id);
    }

    return PWRule(std::move(targets), std::move(transformers), std::move(processor));
}

void parseRule(parameter::map& rule, PWRuleManager& ruleManager, PWManifest& manifest,
               std::unordered_map<std::string, std::vector<std::string>>& flows)
{
    auto id = at<std::string>(rule, "id");
    if (ruleManager.hasRule(id))
    {
        DDWAF_WARN("duplicate rule %s", id.c_str());
        return;
    }

    try
    {
        auto tags = at<parameter::map>(rule, "tags");
        auto type = at<std::string>(tags, "type");

        auto& flow = flows[type];

        std::vector<PW_TRANSFORM_ID> rule_transformers;
        auto transformers = at<parameter::vector>(rule, "transformers", parameter::vector());
        for (std::string_view transformer : transformers)
        {
            PW_TRANSFORM_ID transform_id = PWTransformer::getIDForString(transformer);
            if (transform_id == PWT_INVALID)
            {
                throw parsing_error("invalid transformer" + std::string(transformer));
            }
            rule_transformers.push_back(transform_id);
        }

        std::vector<PWRule> rules;
        parameter::vector conditions = rule.at("conditions");
        for (parameter::map condition : conditions)
        {
            PWRule rule = parseCondition(condition, manifest, rule_transformers);
            rules.push_back(std::move(rule));
        }

        ruleManager.addRule(id, std::move(rules));
        flow.push_back(id);
    }
    catch (const std::exception& e)
    {
        DDWAF_WARN("failed to parse rule '%s': %s", id.c_str(), e.what());
    }
}

}

namespace ddwaf::parser::v1
{

void parse(parameter::map& ruleset, PWRuleManager& ruleManager, PWManifest& manifest,
           std::unordered_map<std::string, std::vector<std::string>>& flows)
{
    auto rules = at<parameter::vector>(ruleset, "events");
    for (parameter::map rule : rules)
    {
        try
        {
            parseRule(rule, ruleManager, manifest, flows);
        }
        catch (const std::exception& e)
        {
            DDWAF_WARN("%s", e.what());
        }
    }

    if (ruleManager.isEmpty() || flows.empty())
    {
        throw parsing_error("no valid rules found");
    }
}

}
