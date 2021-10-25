// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWManifest.h>
#include <PWRetriever.hpp>
#include <exception.hpp>
#include <log.hpp>
#include <parameter.hpp>
#include <parser/common.hpp>
#include <rule.hpp>
#include <string>
#include <unordered_map>
#include <vector>

using ddwaf::parameter;
using ddwaf::parser::at;

namespace
{

ddwaf::condition parseCondition(parameter::map& rule, PWManifest& manifest,
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
                throw ddwaf::parsing_error("phrase_match list item not a string");
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
        throw ddwaf::parsing_error("unknown processor: " + std::string(operation));
    }

    std::vector<PWManifest::ARG_ID> targets;
    auto inputs = at<parameter::vector>(params, "inputs");
    for (std::string input : inputs)
    {
        if (input.empty())
        {
            throw ddwaf::parsing_error("empty address");
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

    return ddwaf::condition(std::move(targets), std::move(transformers), std::move(processor));
}

void parseRule(parameter::map& rule, ddwaf::rule_map& rules,
               PWManifest& manifest, ddwaf::flow_map& flows)
{
    auto id = at<std::string>(rule, "id");
    if (rules.find(id) != rules.end())
    {
        DDWAF_WARN("duplicate rule %s", id.c_str());
        return;
    }

    try
    {
        ddwaf::rule parsed_rule;

        std::vector<PW_TRANSFORM_ID> rule_transformers;
        auto transformers = at<parameter::vector>(rule, "transformers", parameter::vector());
        for (std::string_view transformer : transformers)
        {
            PW_TRANSFORM_ID transform_id = PWTransformer::getIDForString(transformer);
            if (transform_id == PWT_INVALID)
            {
                throw ddwaf::parsing_error("invalid transformer" + std::string(transformer));
            }
            rule_transformers.push_back(transform_id);
        }

        std::vector<ddwaf::condition> conditions;
        parameter::vector conditions_array = rule.at("conditions");
        for (parameter::map cond : conditions_array)
        {
            parsed_rule.conditions.push_back(
                parseCondition(cond, manifest, rule_transformers));
        }

        auto tags = at<parameter::map>(rule, "tags");
        auto type = at<std::string>(tags, "type");

        parsed_rule.name     = at<std::string>(rule, "name");
        parsed_rule.category = at<std::string>(tags, "category", "");

        rules.emplace(id, std::move(parsed_rule));

        auto& flow = flows[type];
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

void parse(parameter::map& ruleset, ddwaf::rule_map& rules,
           PWManifest& manifest, ddwaf::flow_map& flows)
{
    auto rules_array = at<parameter::vector>(ruleset, "events");
    for (parameter::map rule : rules_array)
    {
        try
        {
            parseRule(rule, rules, manifest, flows);
        }
        catch (const std::exception& e)
        {
            DDWAF_WARN("%s", e.what());
        }
    }

    if (rules.empty() || flows.empty())
    {
        throw ddwaf::parsing_error("no valid rules found");
    }

    DDWAF_DEBUG("Loaded %zu rules out of %zu available in the ruleset",
                rules.size(), rules_array.size());
}

}
