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
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <rule_processor/is_sqli.hpp>
#include <rule_processor/is_xss.hpp>
#include <rule_processor/phrase_match.hpp>
#include <rule_processor/regex_match.hpp>
#include <rule_processor/ip_match.hpp>
#include <rule_processor/exact_match.hpp>

using ddwaf::parameter;
using ddwaf::parser::at;
using ddwaf::manifest;
using ddwaf::manifest_builder;
using ddwaf::rule_processor::base;

namespace ddwaf::parser::v2
{

namespace
{

ddwaf::condition parseCondition(parameter::map& rule,
    std::size_t rule_idx, std::size_t cond_idx,
    rule_data::dispatcher_builder &db,
    manifest_builder& mb, ddwaf::condition::data_source source,
    std::vector<PW_TRANSFORM_ID>& transformers,
    ddwaf::config& cfg)
{
    auto operation = at<std::string_view>(rule, "operator");
    auto params    = at<parameter::map>(rule, "parameters");

    parameter::map options;
    std::shared_ptr<base> processor;
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

        processor = std::make_shared<rule_processor::phrase_match>(patterns, lengths);
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

        processor = std::make_shared<rule_processor::regex_match>(
            regex, min_length, case_sensitive);
    }
    else if (operation == "is_xss")
    {
        processor = std::make_shared<rule_processor::is_xss>();
    }
    else if (operation == "is_sqli")
    {
        processor = std::make_shared<rule_processor::is_sqli>();
    }
    else if (operation == "ip_match")
    {
        auto it = params.find("list");
        if (it == params.end()) {
            auto rule_data_id = at<std::string_view>(params, "data");
            db.insert(rule_data_id, "ip_match", rule_idx, cond_idx);
        } else {
            processor = std::make_shared<rule_processor::ip_match>(it->second);
        }
    }
    else if (operation == "exact_match")
    {
        auto it = params.find("list");
        if (it == params.end()) {
            auto rule_data_id = at<std::string_view>(params, "data");
            db.insert(rule_data_id, "exact_match", rule_idx, cond_idx);
        } else {
            processor = std::make_shared<rule_processor::exact_match>(it->second);
        }
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
               rule_data::dispatcher_builder& db,
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

        auto index           = rs.rules.size();

        std::vector<ddwaf::condition> conditions;
        auto conditions_array = at<parameter::vector>(rule, "conditions");
        conditions.reserve(conditions_array.size());

        for (parameter::map cond : conditions_array) {
            conditions.push_back(parseCondition(
                cond, index, conditions.size(),
                db, mb, source, rule_transformers, cfg));
        }

        auto tags = at<parameter::map>(rule, "tags");
        rs.rules.emplace_back(index, std::string(id),
            at<std::string>(rule, "name"),
            at<std::string>(tags, "type"),
            at<std::string>(tags, "category", ""),
            std::move(conditions),
            at<std::vector<std::string>>(rule, "on_match", {}));

        auto &rule_ref = rs.rules[index];

        auto& collection = rs.collections[rule_ref.type];
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

/*{*/
    //"rules_data": [
        //{
            //"id": ip_with_expiration,
            //"type": DATA_TYPE,
            //"data": [
                //{
                    //"value": DATA_VALUE,
                    //( "expiration": TIMESTAMP )
                //}
            //]
        //}
    //]
//}

//void parse_rule_data(parameter::vector& rule_data)
//{
    // This method of parsing generates intermediate structures and requires
    // exception handling which can be slightly more expensive and relevant
    // if done on the hot path, so a potential optimisation could be to parse
    // without intermediate steps.
/*    for (parameter::map entry : rule_data) {*/
        //auto id = at<std::string_view>(entry, "id");
        //auto type = at<std::string_view(entry, "type");

        //switch (
        //auto data = at<parameter::vector>(entry, "data");

        //for 
    /*}*/
//}


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

    rule_data::dispatcher_builder db;
    ddwaf::manifest_builder mb;
    std::set<std::string_view> seen_rules;
    for (parameter::map rule : rules_array)
    {
        try
        {
            parseRule(rule, info, db, mb, rs, seen_rules, cfg);
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
    rs.dispatcher = db.build(rs.rules);
    rs.manifest = mb.build_manifest();

    DDWAF_DEBUG("Loaded %zu rules out of %zu available in the ruleset",
                rs.rules.size(), rules_array.size());
}

}
