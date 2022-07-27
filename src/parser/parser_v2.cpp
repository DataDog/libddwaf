// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <manifest.hpp>
#include <exception.hpp>
#include <log.hpp>
#include <parameter.hpp>
#include <parser/common.hpp>
#include <rule.hpp>
#include <ruleset_info.hpp>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <iostream>

using ddwaf::parameter;
using ddwaf::parser::at;
using ddwaf::manifest;
using ddwaf::manifest_builder;

namespace
{

ddwaf::condition parseCondition(parameter::map& rule, manifest_builder& mb,
    ddwaf::condition::data_source source,
    std::vector<PW_TRANSFORM_ID>& transformers,
    ddwaf::config& cfg)
{
    auto operation = at<std::string_view>(rule, "operator");
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
            lengths.push_back((uint32_t) pattern.nbEntries);
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

        int min_length = 0;
        if (options.find("min_length") != options.end())
        {
            std::string length_opt = options["min_length"];
            try
            {
                min_length = std::stoi(length_opt);
            }
            catch (const std::out_of_range& e)
            {
                throw ddwaf::parsing_error("min_length value too large");
            }
            catch (const std::invalid_argument& e)
            {
                throw ddwaf::parsing_error("min_length not a valid number");
            }

            if (min_length < 0)
            {
                throw ddwaf::parsing_error("min_length is a negative number");
            }
        }

        processor = std::make_unique<RE2Manager>(regex, min_length, case_sensitive);
    }
    else if (operation == "is_xss")
    {
        processor = std::make_unique<LibInjectionXSS>();
    }
    else if (operation == "is_sqli")
    {
        processor = std::make_unique<LibInjectionSQL>();
    }
    else if (operation == "ip_match")
    {
        auto list = at<parameter::vector>(params, "list");

        std::vector<std::string> ips;
        ips.reserve(list.size());

        for (auto& ip : list) {
            ips.push_back(std::move(ip));
        }

        processor = std::make_unique<ip_match>(std::move(ips));
    }
    else
    {
        throw ddwaf::parsing_error("unknown processor: " + std::string(operation));
    }

    std::vector<manifest::target_type> targets;
    auto inputs = at<parameter::vector>(params, "inputs");
    if (inputs.empty())
    {
        throw ddwaf::parsing_error("empty inputs");
    }

    for (parameter::map input : inputs)
    {
        auto address   = at<std::string>(input, "address");
        auto key_paths = at<parameter::vector>(input, "key_path", parameter::vector());

        if (address.empty())
        {
            throw ddwaf::parsing_error("empty address");
        }

        std::vector<std::string> kp;
        for (std::string path : key_paths)
        {
            if (path.empty())
            {
                throw ddwaf::parsing_error("empty key_path");
            }

            kp.push_back(std::move(path));
        }

        auto target = mb.insert(address, std::move(kp));
        targets.push_back(target);
    }

    return ddwaf::condition(std::move(targets), std::move(transformers),
                std::move(processor), cfg.limits, source);
}

void parseRule(parameter::map& rule, ddwaf::ruleset_info& info,
               manifest_builder& mb, ddwaf::ruleset& rs,
               std::set<std::string_view> &seen_rules,
               ddwaf::config& cfg)
{
    auto id = at<std::string>(rule, "id");
    if (seen_rules.find(id) != seen_rules.end())
    {
        DDWAF_WARN("duplicate rule %s", id.c_str());
        info.insert_error(id, "duplicate rule");
        return;
    }

    try
    {
        std::vector<PW_TRANSFORM_ID> rule_transformers;
        auto source = ddwaf::condition::data_source::values;
        auto transformers                  = at<parameter::vector>(rule, "transformers", parameter::vector());
        for (std::string_view transformer : transformers)
        {
            PW_TRANSFORM_ID transform_id = PWTransformer::getIDForString(transformer);
            if (transform_id == PWT_INVALID)
            {
                throw ddwaf::parsing_error("invalid transformer " + std::string(transformer));
            }
            else if (transform_id == PWT_KEYS_ONLY)
            {
                if (!rule_transformers.empty())
                {
                    DDWAF_WARN("keys_only transformer should be the first one "
                               "in the list, all transformers will be applied to "
                               "keys and not values");
                }
                source = ddwaf::condition::data_source::keys;
            }
            else
            {
                rule_transformers.push_back(transform_id);
            }
        }

        std::vector<ddwaf::condition> conditions;
        auto conditions_array = at<parameter::vector>(rule, "conditions");
        for (parameter::map cond : conditions_array)
        {
            conditions.push_back(parseCondition(cond, mb, source, rule_transformers, cfg));
        }

        auto tags = at<parameter::map>(rule, "tags");
        auto type = at<std::string>(tags, "type");

        auto index           = rs.rules.size();
        rs.rules.emplace_back(index, std::string(id),
            at<std::string>(rule, "name"),
            at<std::string>(tags, "category", ""),
            std::move(conditions));

        auto &rule_ref = rs.rules[index];

        auto& collection = rs.collections[type];
        collection.push_back(rule_ref);

        // Add this rule to the set to check for duplicates
        seen_rules.emplace(rule_ref.id);

        info.add_loaded();
    }
    catch (const std::exception& e)
    {
        DDWAF_WARN("failed to parse rule '%s': %s", id.c_str(), e.what());
        info.insert_error(id, e.what());
    }
}

}

namespace ddwaf::parser::v2
{

void parse(parameter::map& ruleset, ruleset_info& info,  ddwaf::ruleset& rs, ddwaf::config& cfg)
{
    auto metadata      = at<parameter::map>(ruleset, "metadata", parameter::map());
    auto rules_version = metadata.find("rules_version");
    if (rules_version != metadata.end())
    {
        info.set_version(rules_version->second);
    }

    auto rules_array = at<parameter::vector>(ruleset, "rules");
    // Note that reserving elements is required to ensure all references
    // are valid, otherwise reallocations would invalidate them.
    rs.rules.reserve(rules_array.size());

    ddwaf::manifest_builder mb;
    std::set<std::string_view> seen_rules;
    for (parameter::map rule : rules_array)
    {
        try
        {
            parseRule(rule, info, mb, rs, seen_rules, cfg);
        }
        catch (const std::exception& e)
        {
            DDWAF_WARN("%s", e.what());
            info.add_failed();
        }
    }

    if (rs.rules.empty() || rs.collections.empty())
    {
        throw ddwaf::parsing_error("no valid rules found");
    }

    rs.manifest = mb.build_manifest();

    DDWAF_DEBUG("Loaded %zu rules out of %zu available in the ruleset",
                rs.rules.size(), rules_array.size());
}

}
