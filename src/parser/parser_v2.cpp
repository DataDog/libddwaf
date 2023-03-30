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
#include <parser/rule_data_parser.hpp>
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

namespace {

std::pair<std::string, rule_processor::base::ptr> parse_processor(
    std::string_view operation, const parameter::map &params)
{
    parameter::map options;
    std::shared_ptr<base> processor;
    std::string rule_data_id;

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
        } else {
            processor = std::make_shared<rule_processor::ip_match>(
                static_cast<std::vector<std::string_view>>(it->second));
        }
    } else if (operation == "exact_match") {
        auto it = params.find("list");
        if (it == params.end()) {
            rule_data_id = at<std::string>(params, "data");
        } else {
            processor = std::make_shared<rule_processor::exact_match>(
                static_cast<std::vector<std::string>>(it->second));
        }
    } else {
        throw ddwaf::parsing_error("unknown processor: " + std::string(operation));
    }

    return {std::move(rule_data_id), std::move(processor)};
}

condition::ptr parse_rule_condition(const parameter::map &root, manifest &target_manifest,
    std::unordered_map<std::string, std::string> &rule_data_ids, condition::data_source source,
    std::vector<PW_TRANSFORM_ID> transformers, const object_limits &limits)
{
    auto operation = at<std::string_view>(root, "operator");
    auto params = at<parameter::map>(root, "parameters");

    auto [rule_data_id, processor] = parse_processor(operation, params);
    if (!processor && !rule_data_id.empty()) {
        rule_data_ids.emplace(rule_data_id, operation);
    }
    std::vector<condition::target_type> targets;
    auto inputs = at<parameter::vector>(params, "inputs");
    if (inputs.empty()) {
        throw ddwaf::parsing_error("empty inputs");
    }

    for (const auto &input_param : inputs) {
        auto input = static_cast<parameter::map>(input_param);
        auto address = at<std::string>(input, "address");

        if (address.empty()) {
            throw ddwaf::parsing_error("empty address");
        }

        auto kp = at<std::vector<std::string>>(input, "key_path", {});
        for (const auto &path : kp) {
            if (path.empty()) {
                throw ddwaf::parsing_error("empty key_path");
            }
        }

        condition::target_type target;
        target.root = target_manifest.insert(address);
        target.name = address;
        target.key_path = std::move(kp);

        targets.emplace_back(target);
    }

    return std::make_shared<condition>(std::move(targets), std::move(transformers),
        std::move(processor), std::move(rule_data_id), limits, source);
}

rule_spec parse_rule(parameter::map &rule, manifest &target_manifest,
    std::unordered_map<std::string, std::string> &rule_data_ids, const object_limits &limits,
    rule::source_type source)
{
    std::vector<PW_TRANSFORM_ID> rule_transformers;
    auto data_source = ddwaf::condition::data_source::values;
    auto transformers = at<parameter::vector>(rule, "transformers", {});
    for (const auto &transformer_param : transformers) {
        auto transformer = static_cast<std::string_view>(transformer_param);
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
            data_source = ddwaf::condition::data_source::keys;
        } else {
            rule_transformers.push_back(transform_id);
        }
    }

    std::vector<condition::ptr> conditions;
    auto conditions_array = at<parameter::vector>(rule, "conditions");
    conditions.reserve(conditions_array.size());

    for (const auto &cond_param : conditions_array) {
        auto cond = static_cast<parameter::map>(cond_param);
        conditions.push_back(parse_rule_condition(
            cond, target_manifest, rule_data_ids, data_source, rule_transformers, limits));
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

    return {at<bool>(rule, "enabled", true), source, at<std::string>(rule, "name"), std::move(tags),
        std::move(conditions), at<std::vector<std::string>>(rule, "on_match", {})};
}

rule_target_spec parse_rules_target(const parameter::map &target)
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

std::pair<override_spec, target_type> parse_override(const parameter::map &node)
{
    // Note that ID is a duplicate field and will be deprecated at some point
    override_spec current;

    auto it = node.find("enabled");
    if (it != node.end()) {
        current.enabled = static_cast<bool>(it->second);
    }

    it = node.find("on_match");
    if (it != node.end()) {
        auto actions = static_cast<std::vector<std::string>>(it->second);
        current.actions = std::move(actions);
    }

    target_type type = target_type::none;

    auto rules_target_array = at<parameter::vector>(node, "rules_target", {});
    if (!rules_target_array.empty()) {
        current.targets.reserve(rules_target_array.size());

        for (const auto &target : rules_target_array) {
            auto target_spec = parse_rules_target(static_cast<parameter::map>(target));
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

condition::ptr parse_filter_condition(
    const parameter::map &root, manifest &target_manifest, const object_limits &limits)
{
    auto operation = at<std::string_view>(root, "operator");
    auto params = at<parameter::map>(root, "parameters");

    auto [rule_data_id, processor] = parse_processor(operation, params);
    if (!rule_data_id.empty()) {
        throw ddwaf::parsing_error("filter conditions don't support dynamic data");
    }

    std::vector<condition::target_type> targets;
    auto inputs = at<parameter::vector>(params, "inputs");
    if (inputs.empty()) {
        throw ddwaf::parsing_error("empty inputs");
    }

    for (const auto &input_param : inputs) {
        auto input = static_cast<parameter::map>(input_param);

        auto address = at<std::string>(input, "address");
        if (address.empty()) {
            throw ddwaf::parsing_error("empty address");
        }

        auto key_path = at<std::vector<std::string>>(input, "key_path", {});
        for (const auto &path : key_path) {
            if (path.empty()) {
                throw ddwaf::parsing_error("empty key_path");
            }
        }

        condition::target_type target;
        target.root = target_manifest.insert(address);
        target.name = address;
        target.key_path = std::move(key_path);

        targets.emplace_back(target);
    }

    return std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::move(processor), std::string{}, limits);
}

input_filter_spec parse_input_filter(
    const parameter::map &filter, manifest &target_manifest, const object_limits &limits)

{
    // Check for conditions first
    std::vector<condition::ptr> conditions;
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    if (!conditions_array.empty()) {
        conditions.reserve(conditions_array.size());

        for (const auto &cond : conditions_array) {
            conditions.push_back(
                parse_filter_condition(static_cast<parameter::map>(cond), target_manifest, limits));
        }
    }

    std::vector<rule_target_spec> rules_target;
    auto rules_target_array = at<parameter::vector>(filter, "rules_target", {});
    if (!rules_target_array.empty()) {
        rules_target.reserve(rules_target_array.size());

        for (const auto &target : rules_target_array) {
            rules_target.emplace_back(parse_rules_target(static_cast<parameter::map>(target)));
        }
    }

    std::unordered_set<manifest::target_type> input_targets;
    auto obj_filter = std::make_shared<exclusion::object_filter>(limits);
    auto inputs_array = at<parameter::vector>(filter, "inputs");

    // TODO: add empty method to object filter and check after
    if (conditions.empty() && inputs_array.empty() && rules_target.empty()) {
        throw ddwaf::parsing_error("empty exclusion filter");
    }

    for (const auto &input_param : inputs_array) {
        auto input_map = static_cast<parameter::map>(input_param);
        auto address = at<std::string>(input_map, "address");

        auto optional_target = target_manifest.find(address);
        if (!optional_target.has_value()) {
            // This address isn't used by any rule so we skip it.
            DDWAF_DEBUG("Address %s not used by any existing rule", address.c_str());
            continue;
        }

        auto key_path = at<std::vector<std::string_view>>(input_map, "key_path", {});

        obj_filter->insert(*optional_target, key_path);
    }

    return {std::move(conditions), std::move(obj_filter), std::move(rules_target)};
}

rule_filter_spec parse_rule_filter(
    const parameter::map &filter, manifest &target_manifest, const object_limits &limits)
{
    // Check for conditions first
    std::vector<condition::ptr> conditions;
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    if (!conditions_array.empty()) {
        conditions.reserve(conditions_array.size());

        for (const auto &cond : conditions_array) {
            conditions.push_back(
                parse_filter_condition(static_cast<parameter::map>(cond), target_manifest, limits));
        }
    }

    std::vector<rule_target_spec> rules_target;
    auto rules_target_array = at<parameter::vector>(filter, "rules_target", {});
    if (!rules_target_array.empty()) {
        rules_target.reserve(rules_target_array.size());

        for (const auto &target : rules_target_array) {
            rules_target.emplace_back(parse_rules_target(static_cast<parameter::map>(target)));
        }
    }

    if (conditions.empty() && rules_target.empty()) {
        throw ddwaf::parsing_error("empty exclusion filter");
    }

    return {std::move(conditions), std::move(rules_target)};
}

} // namespace

rule_spec_container parse_rules(parameter::vector &rule_array, ddwaf::ruleset_info &info,
    manifest &target_manifest, std::unordered_map<std::string, std::string> &rule_data_ids,
    const object_limits &limits, rule::source_type source)
{
    rule_spec_container rules;
    for (const auto &rule_param : rule_array) {
        auto rule_map = static_cast<parameter::map>(rule_param);
        std::string id;
        try {
            id = at<std::string>(rule_map, "id");
            if (rules.find(id) != rules.end()) {
                DDWAF_WARN("duplicate rule %s", id.c_str());
                info.insert_error(id, "duplicate rule");
                continue;
            }

            auto rule = parse_rule(rule_map, target_manifest, rule_data_ids, limits, source);
            rules.emplace(std::move(id), std::move(rule));
            info.add_loaded();
        } catch (const std::exception &e) {
            if (!id.empty()) {
                DDWAF_WARN("failed to parse rule '%s': %s", id.c_str(), e.what());
                info.insert_error(id, e.what());
            } else {
                DDWAF_WARN("failed to parse rule: %s", e.what());
                info.add_failed();
            }
        }
    }

    return rules;
}

rule_data_container parse_rule_data(
    parameter::vector &rule_data, std::unordered_map<std::string, std::string> &rule_data_ids)
{
    rule_data_container processors;
    for (ddwaf::parameter object : rule_data) {
        std::string id;
        try {
            auto entry = static_cast<ddwaf::parameter::map>(object);

            id = at<std::string>(entry, "id");

            auto type = at<std::string_view>(entry, "type");
            auto data = at<parameter>(entry, "data");

            std::string_view operation;
            auto it = rule_data_ids.find(id);
            if (it == rule_data_ids.end()) {
                // Infer processor from data type
                if (type == "ip_with_expiration") {
                    operation = "ip_match";
                } else if (type == "data_with_expiration") {
                    operation = "exact_match";
                } else {
                    DDWAF_DEBUG("Failed to process rule idata id '%s", id.c_str());
                }
            } else {
                operation = it->second;
            }

            rule_processor::base::ptr processor;
            if (operation == "ip_match") {
                using rule_data_type = rule_processor::ip_match::rule_data_type;
                auto parsed_data = parser::parse_rule_data<rule_data_type>(type, data);
                processor = std::make_shared<rule_processor::ip_match>(parsed_data);
            } else if (operation == "exact_match") {
                using rule_data_type = rule_processor::exact_match::rule_data_type;
                auto parsed_data = parser::parse_rule_data<rule_data_type>(type, data);
                processor = std::make_shared<rule_processor::exact_match>(parsed_data);
            } else {
                DDWAF_WARN("Processor %.*s doesn't support dynamic rule data",
                    static_cast<int>(operation.length()), operation.data());
                continue;
            }

            processors.emplace(std::move(id), std::move(processor));
        } catch (const ddwaf::exception &e) {
            DDWAF_ERROR("Failed to parse data id '%s': %s",
                (!id.empty() ? id.c_str() : "(unknown)"), e.what());
        }
    }

    return processors;
}

override_spec_container parse_overrides(parameter::vector &override_array)
{
    override_spec_container overrides;

    for (const auto &node_param : override_array) {
        auto node = static_cast<parameter::map>(node_param);
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

filter_spec_container parse_filters(
    parameter::vector &filter_array, manifest &target_manifest, const object_limits &limits)
{
    filter_spec_container filters;
    for (const auto &node_param : filter_array) {
        auto node = static_cast<parameter::map>(node_param);
        std::string id;
        try {
            id = at<std::string>(node, "id");
            if (filters.ids.find(id) != filters.ids.end()) {
                DDWAF_WARN("duplicate filter: %s", id.c_str());
                continue;
            }

            if (node.find("inputs") != node.end()) {
                auto filter = parse_input_filter(node, target_manifest, limits);
                filters.ids.emplace(id);
                filters.input_filters.emplace(std::move(id), std::move(filter));
            } else {
                auto filter = parse_rule_filter(node, target_manifest, limits);
                filters.ids.emplace(id);
                filters.rule_filters.emplace(std::move(id), std::move(filter));
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
