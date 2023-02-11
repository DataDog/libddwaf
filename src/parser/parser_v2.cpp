// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWTransformer.h>
#include <algorithm>
#include <exception.hpp>
#include <exclusion/object_filter.hpp>
#include <log.hpp>
#include <manifest.hpp>
#include <parameter.hpp>
#include <parser/common.hpp>
#include <parser/parser.hpp>
#include <parser/specification.hpp>
#include <rule.hpp>
#include <rule_processor/exact_match.hpp>
#include <rule_processor/ip_match.hpp>
#include <rule_processor/is_sqli.hpp>
#include <rule_processor/is_xss.hpp>
#include <rule_processor/phrase_match.hpp>
#include <rule_processor/regex_match.hpp>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

using ddwaf::rule_processor::base;

namespace ddwaf::parser::v2 {

condition::ptr parser::parse_condition(
    parameter::map &root, condition::data_source source, std::vector<PW_TRANSFORM_ID> transformers)
{
    auto operation = at<std::string_view>(root, "operator");
    auto params = at<parameter::map>(root, "parameters");
    bool is_mutable = false;

    parameter::map options;
    std::shared_ptr<base> processor;
    std::optional<std::string> rule_data_id = std::nullopt;
    if (operation == "phrase_match") {
        auto list = at<parameter::vector>(params, "list");

        std::vector<const char *> patterns;
        std::vector<uint32_t> lengths;

        patterns.reserve(list.size());
        lengths.reserve(list.size());

        for (auto &pattern : list) {
            if (pattern.type != DDWAF_OBJ_STRING) {
                throw ddwaf::parsing_error("phrase_match list item not a string");
            }

            patterns.push_back(pattern.stringValue);
            lengths.push_back((uint32_t)pattern.nbEntries);
        }

        processor = std::make_shared<rule_processor::phrase_match>(patterns, lengths);
    } else if (operation == "match_regex") {
        auto regex = at<std::string>(params, "regex");
        options = at<parameter::map>(params, "options", options);

        auto case_sensitive = at<bool>(options, "case_sensitive", false);
        auto min_length = at<int64_t>(options, "min_length", 0);
        if (min_length < 0) {
            throw ddwaf::parsing_error("min_length is a negative number");
        }

        processor =
            std::make_shared<rule_processor::regex_match>(regex, min_length, case_sensitive);
    } else if (operation == "is_xss") {
        processor = std::make_shared<rule_processor::is_xss>();
    } else if (operation == "is_sqli") {
        processor = std::make_shared<rule_processor::is_sqli>();
    } else if (operation == "ip_match") {
        auto it = params.find("list");
        if (it == params.end()) {
            rule_data_id = at<std::string>(params, "data");
            processor = std::make_shared<rule_processor::ip_match>();
            is_mutable = true;
        } else {
            processor = std::make_shared<rule_processor::ip_match>(it->second);
        }
    } else if (operation == "exact_match") {
        auto it = params.find("list");
        if (it == params.end()) {
            rule_data_id = at<std::string>(params, "data");
            processor = std::make_shared<rule_processor::exact_match>();
            is_mutable = true;
        } else {
            processor = std::make_shared<rule_processor::exact_match>(it->second);
        }
    } else {
        throw ddwaf::parsing_error("unknown processor: " + std::string(operation));
    }

    std::vector<condition::target_type> targets;
    auto inputs = at<parameter::vector>(params, "inputs");
    if (inputs.empty()) {
        throw ddwaf::parsing_error("empty inputs");
    }

    for (parameter::map input : inputs) {
        auto address = at<std::string>(input, "address");
        auto key_paths = at<parameter::vector>(input, "key_path", parameter::vector());

        if (address.empty()) {
            throw ddwaf::parsing_error("empty address");
        }

        std::vector<std::string> kp;
        for (std::string path : key_paths) {
            if (path.empty()) {
                throw ddwaf::parsing_error("empty key_path");
            }

            kp.push_back(std::move(path));
        }

        condition::target_type target;
        target.root = target_manifest_.insert(address);
        target.name = address;
        target.key_path = std::move(kp);

        targets.emplace_back(target);
    }

    auto cond = std::make_shared<condition>(std::move(targets), std::move(transformers),
        std::move(processor), limits_, source, is_mutable);

    if (rule_data_id.has_value()) {
        if (operation == "ip_match") {
            dispatcher_.register_condition<rule_processor::ip_match>(*rule_data_id, cond);
        } else if (operation == "exact_match") {
            dispatcher_.register_condition<rule_processor::exact_match>(*rule_data_id, cond);
        }
    }

    return cond;
}

rule_spec parser::parse_rule(parameter::map &rule)
{
    std::vector<PW_TRANSFORM_ID> rule_transformers;
    auto source = ddwaf::condition::data_source::values;
    auto transformers = at<parameter::vector>(rule, "transformers", parameter::vector());
    for (std::string_view transformer : transformers) {
        PW_TRANSFORM_ID transform_id = PWTransformer::getIDForString(transformer);
        if (transform_id == PWT_INVALID) {
            throw ddwaf::parsing_error("invalid transformer " + std::string(transformer));
        }

        if (transform_id == PWT_KEYS_ONLY) {
            if (!rule_transformers.empty()) {
                DDWAF_WARN("keys_only transformer should be the first one "
                           "in the list, all transformers will be applied to "
                           "keys and not values");
            }
            source = ddwaf::condition::data_source::keys;
        } else {
            rule_transformers.push_back(transform_id);
        }
    }

    std::vector<condition::ptr> conditions;
    auto conditions_array = at<parameter::vector>(rule, "conditions");
    conditions.reserve(conditions_array.size());

    for (parameter::map cond : conditions_array) {
        conditions.push_back(parse_condition(cond, source, rule_transformers));
    }

    std::unordered_map<std::string, std::string> tags;
    for (auto &[key, value] : at<parameter::map>(rule, "tags")) {
        try {
            tags.emplace(key, std::string(value));
        } catch (const bad_cast &e) {
            throw invalid_type(std::string(key), e);
        }
    }

    if (tags.find("type") == tags.end()) {
        throw ddwaf::parsing_error("missing key 'type'");
    }

    return {at<bool>(rule, "enabled", true), at<std::string>(rule, "name"), std::move(tags),
        std::move(conditions), at<std::vector<std::string>>(rule, "on_match", {})};
}

rule_spec_container parser::parse_rules(parameter::vector &rule_array)
{
    rule_spec_container rules;
    for (parameter::map rule_map : rule_array) {
        std::string id;
        try {
            id = at<std::string>(rule_map, "id");
            if (rules.find(id) != rules.end()) {
                DDWAF_WARN("duplicate rule %s", id.c_str());
                info_.insert_error(id, "duplicate rule");
                continue;
            }

            auto rule = parse_rule(rule_map);
            rules.emplace(std::move(id), std::move(rule));
            info_.add_loaded();
        } catch (const std::exception &e) {
            if (!id.empty()) {
                DDWAF_WARN("failed to parse rule '%s': %s", id.c_str(), e.what());
                info_.insert_error(id, e.what());
            } else {
                DDWAF_WARN("failed to parse rule: %s", e.what());
                info_.add_failed();
            }
        }
    }

    return rules;
}

rule_target_spec parse_rules_target(parameter::map &target)
{
    auto rule_id = at<std::string>(target, "rule_id", {});
    if (!rule_id.empty()) {
        return {target_type::id, std::move(rule_id), {}};
    }

    auto tag_map = at<parameter::map>(target, "tags", {});
    if (tag_map.empty()) {
        throw ddwaf::parsing_error("empty rules_target");
    }

    std::unordered_map<std::string, std::string> tags;
    for (auto &[key, value] : tag_map) { tags.emplace(key, value); }

    return {target_type::tags, {}, std::move(tags)};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<override_spec, target_type> parser::parse_override(parameter::map &node)
{
    // Note that ID is a duplicate field and will be deprecated at some point
    override_spec current;

    auto it = node.find("enabled");
    if (it != node.end()) {
        current.enabled = it->second;
    }

    it = node.find("on_match");
    if (it != node.end()) {
        current.actions = it->second;
    }

    target_type type = target_type::none;

    auto rules_target_array = at<parameter::vector>(node, "rules_target", {});
    if (!rules_target_array.empty()) {
        current.targets.reserve(rules_target_array.size());

        for (parameter::map target : rules_target_array) {
            auto target_spec = parse_rules_target(target);
            if (type == target_type::none) {
                type = target_spec.type;
            } else if (type != target_spec.type) {
                throw ddwaf::parsing_error("rule_override targets rules and tags");
            }

            current.targets.emplace_back(std::move(target_spec));
        }
    } else {
        // Since the rules_target array is empty, the ID is mandatory
        current.targets.emplace_back(
            rule_target_spec{target_type::id, at<std::string>(node, "id"), {}});
        type = target_type::id;
    }

    if (!current.actions.has_value() && !current.enabled.has_value()) {
        throw ddwaf::parsing_error("rules_override without side-effects");
    }

    return {current, type};
}

override_spec_container parser::parse_overrides(parameter::vector &override_array)
{
    override_spec_container overrides;

    for (parameter::map node : override_array) {
        try {
            auto [spec, type] = parse_override(node);
            if (type == target_type::id) {
                overrides.by_ids.emplace_back(std::move(spec));
            } else if (type == target_type::tags) {
                overrides.by_tags.emplace_back(std::move(spec));
            } else {
                DDWAF_WARN("override with no targets");
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("failed to parse rule_override: %s", e.what());
        }
    }

    return overrides;
}

input_filter_spec parser::parse_input_filter(parameter::map &filter)
{
    // Check for conditions first
    std::vector<condition::ptr> conditions;
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    if (!conditions_array.empty()) {
        conditions.reserve(conditions_array.size());

        for (parameter::map cond : conditions_array) {
            conditions.push_back(parse_condition(cond));
        }
    }

    std::vector<rule_target_spec> rules_target;
    auto rules_target_array = at<parameter::vector>(filter, "rules_target", {});
    if (!rules_target_array.empty()) {
        rules_target.reserve(rules_target_array.size());

        for (parameter::map target : rules_target_array) {
            rules_target.emplace_back(parse_rules_target(target));
        }
    }

    std::unordered_set<manifest::target_type> input_targets;
    exclusion::object_filter obj_filter{limits_};
    auto inputs_array = at<parameter::vector>(filter, "inputs");
    for (parameter::map input_map : inputs_array) {
        auto address = at<std::string>(input_map, "address");

        auto optional_target = target_manifest_.find(address);
        if (!optional_target.has_value()) {
            // This address isn't used by any rule so we skip it.
            throw ddwaf::parsing_error("Address " + address + " not used by any existing rule");
        }

        auto key_path = at<std::vector<std::string_view>>(input_map, "key_path", {});

        obj_filter.insert(*optional_target, key_path);
    }

    return {std::move(conditions), std::move(obj_filter), std::move(rules_target)};
}

rule_filter_spec parser::parse_rule_filter(parameter::map &filter)
{
    // Check for conditions first
    std::vector<condition::ptr> conditions;
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    if (!conditions_array.empty()) {
        conditions.reserve(conditions_array.size());

        for (parameter::map cond : conditions_array) {
            conditions.push_back(parse_condition(cond));
        }
    }

    std::vector<rule_target_spec> rules_target;
    auto rules_target_array = at<parameter::vector>(filter, "rules_target", {});
    if (!rules_target_array.empty()) {
        rules_target.reserve(rules_target_array.size());

        for (parameter::map target : rules_target_array) {
            rules_target.emplace_back(parse_rules_target(target));
        }
    }

    if (conditions.empty() && rules_target.empty()) {
        throw ddwaf::parsing_error("empty exclusion filter");
    }

    return {std::move(conditions), std::move(rules_target)};
}

filter_spec_container parser::parse_filters(parameter::vector &filter_array)
{
    filter_spec_container filters;
    for (parameter::map node : filter_array) {
        std::string id;
        try {
            id = at<std::string>(node, "id");
            if (filters.rule_filters.find(id) != filters.rule_filters.end() ||
                filters.input_filters.find(id) != filters.input_filters.end()) {
                DDWAF_WARN("duplicate filter: %s", id.c_str());
                continue;
            }

            if (node.find("inputs") != node.end()) {
                auto filter = parse_input_filter(node);
                filters.input_filters.emplace(id, std::move(filter));
            } else {
                auto filter = parse_rule_filter(node);
                if (filter.conditions.empty()) {
                    filters.unconditional_rule_filters.emplace(std::move(id), std::move(filter));
                } else {
                    filters.rule_filters.emplace(std::move(id), std::move(filter));
                }
            }
        } catch (const std::exception &e) {
            if (!id.empty()) {
                DDWAF_WARN("failed to parse filter '%s': %s", id.c_str(), e.what());
            } else {
                DDWAF_WARN("failed to parse filter: %s", e.what());
            }
        }
    }

    return filters;
}

} // namespace ddwaf::parser::v2
