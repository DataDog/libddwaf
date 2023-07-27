// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "generator/extract_schema.hpp"
#include "utils.hpp"
#include <algorithm>
#include <exception.hpp>
#include <exclusion/object_filter.hpp>
#include <log.hpp>
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

std::vector<transformer_id> parse_transformers(
    const parameter::vector &root, condition::data_source &source)
{
    if (root.empty()) {
        return {};
    }

    std::vector<transformer_id> transformers;
    transformers.reserve(root.size());

    for (const auto &transformer_param : root) {
        auto transformer = static_cast<std::string_view>(transformer_param);
        auto id = transformer_from_string(transformer);
        if (id.has_value()) {
            transformers.emplace_back(id.value());
        } else if (transformer == "keys_only") {
            source = ddwaf::condition::data_source::keys;
        } else if (transformer == "values_only") {
            source = ddwaf::condition::data_source::values;
        } else {
            throw ddwaf::parsing_error("invalid transformer " + std::string(transformer));
        }
    }
    return transformers;
}

condition::ptr parse_rule_condition(const parameter::map &root,
    std::unordered_map<std::string, std::string> &rule_data_ids, condition::data_source source,
    const std::vector<transformer_id> &transformers, const object_limits &limits)
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
        target.root = get_target_index(address);
        target.name = address;
        target.key_path = std::move(kp);

        auto it = input.find("transformers");
        if (it == input.end()) {
            target.source = source;
            target.transformers = transformers;
        } else {
            auto input_transformers = static_cast<parameter::vector>(it->second);
            target.source = condition::data_source::values;
            target.transformers = parse_transformers(input_transformers, target.source);
        }
        targets.emplace_back(target);
    }

    return std::make_shared<condition>(
        std::move(targets), std::move(processor), std::move(rule_data_id), limits);
}

rule_spec parse_rule(parameter::map &rule,
    std::unordered_map<std::string, std::string> &rule_data_ids, const object_limits &limits,
    rule::source_type source)
{
    std::vector<transformer_id> rule_transformers;
    auto data_source = ddwaf::condition::data_source::values;
    auto transformers = at<parameter::vector>(rule, "transformers", {});
    rule_transformers = parse_transformers(transformers, data_source);

    std::vector<condition::ptr> conditions;
    auto conditions_array = at<parameter::vector>(rule, "conditions");
    conditions.reserve(conditions_array.size());

    for (const auto &cond_param : conditions_array) {
        auto cond = static_cast<parameter::map>(cond_param);
        conditions.push_back(
            parse_rule_condition(cond, rule_data_ids, data_source, rule_transformers, limits));
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
    if (!tag_map.empty()) {
        std::unordered_map<std::string, std::string> tags;
        for (auto &[key, value] : tag_map) { tags.emplace(key, value); }

        return {target_type::tags, {}, std::move(tags)};
    }

    return {target_type::none, {}, {}};
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
                throw ddwaf::parsing_error("rule override targets rules and tags");
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
        throw ddwaf::parsing_error("rule override without side-effects");
    }

    return {current, type};
}

condition::ptr parse_simplified_condition(const parameter::map &root, const object_limits &limits)
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
        target.root = get_target_index(address);
        target.name = address;
        target.key_path = std::move(key_path);
        target.source = condition::data_source::values;

        auto it = input.find("transformers");
        if (it != input.end()) {
            auto input_transformers = static_cast<parameter::vector>(it->second);
            target.transformers = parse_transformers(input_transformers, target.source);
        }

        targets.emplace_back(target);
    }

    return std::make_shared<condition>(
        std::move(targets), std::move(processor), std::string{}, limits);
}

input_filter_spec parse_input_filter(const parameter::map &filter, const object_limits &limits)
{
    // Check for conditions first
    std::vector<condition::ptr> conditions;
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    if (!conditions_array.empty()) {
        conditions.reserve(conditions_array.size());

        for (const auto &cond : conditions_array) {
            conditions.push_back(
                parse_simplified_condition(static_cast<parameter::map>(cond), limits));
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

    std::unordered_set<target_index> input_targets;
    auto obj_filter = std::make_shared<exclusion::object_filter>(limits);
    auto inputs_array = at<parameter::vector>(filter, "inputs");

    // TODO: add empty method to object filter and check after
    if (conditions.empty() && inputs_array.empty() && rules_target.empty()) {
        throw ddwaf::parsing_error("empty exclusion filter");
    }

    for (const auto &input_param : inputs_array) {
        auto input_map = static_cast<parameter::map>(input_param);
        auto address = at<std::string>(input_map, "address");

        auto target = get_target_index(address);
        auto key_path = at<std::vector<std::string_view>>(input_map, "key_path", {});

        obj_filter->insert(target, std::move(address), key_path);
    }

    return {std::move(conditions), std::move(obj_filter), std::move(rules_target)};
}

rule_filter_spec parse_rule_filter(const parameter::map &filter, const object_limits &limits)
{
    // Check for conditions first
    std::vector<condition::ptr> conditions;
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    if (!conditions_array.empty()) {
        conditions.reserve(conditions_array.size());

        for (const auto &cond : conditions_array) {
            conditions.push_back(
                parse_simplified_condition(static_cast<parameter::map>(cond), limits));
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

    exclusion::filter_mode on_match;
    auto on_match_str = at<std::string_view>(filter, "on_match", "bypass");
    if (on_match_str == "bypass") {
        on_match = exclusion::filter_mode::bypass;
    } else if (on_match_str == "monitor") {
        on_match = exclusion::filter_mode::monitor;
    } else {
        throw ddwaf::parsing_error("unsupported on_match value: " + std::string(on_match_str));
    }

    if (conditions.empty() && rules_target.empty()) {
        throw ddwaf::parsing_error("empty exclusion filter");
    }

    return {std::move(conditions), std::move(rules_target), on_match};
}

std::vector<preprocessor::target_mapping> parse_preprocessor_mappings(const parameter::vector &root)
{
    if (root.empty()) {
        throw ddwaf::parsing_error("empty mappings");
    }

    std::vector<preprocessor::target_mapping> mappings;
    for (const auto &node : root) {
        auto mapping = static_cast<parameter::map>(node);

        // TODO support n:1 mappings and key paths
        auto inputs = at<parameter::vector>(mapping, "inputs");
        if (inputs.empty()) {
            throw ddwaf::parsing_error("empty preprocessor input mapping");
        }

        auto input = static_cast<parameter::map>(inputs[0]);
        auto input_address = at<std::string_view>(input, "address");
        auto output = at<std::string>(mapping, "output");

        mappings.emplace_back(preprocessor::target_mapping{
            get_target_index(input_address), get_target_index(output), std::move(output)});
    }

    return mappings;
}

std::string index_to_id(unsigned idx) { return "index:" + std::to_string(idx); }

} // namespace

rule_spec_container parse_rules(parameter::vector &rule_array, base_section_info &info,
    std::unordered_map<std::string, std::string> &rule_data_ids, const object_limits &limits,
    rule::source_type source)
{
    rule_spec_container rules;
    for (unsigned i = 0; i < rule_array.size(); ++i) {
        const auto &rule_param = rule_array[i];
        auto rule_map = static_cast<parameter::map>(rule_param);
        std::string id;
        try {
            id = at<std::string>(rule_map, "id");
            if (rules.find(id) != rules.end()) {
                DDWAF_WARN("Duplicate rule %s", id.c_str());
                info.add_failed(id, "duplicate rule");
                continue;
            }

            auto rule = parse_rule(rule_map, rule_data_ids, limits, source);
            DDWAF_DEBUG("Parsed rule %s", id.c_str());
            info.add_loaded(id);
            rules.emplace(std::move(id), std::move(rule));
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse rule '%s': %s", id.c_str(), e.what());
            info.add_failed(id, e.what());
        }
    }

    return rules;
}

rule_data_container parse_rule_data(parameter::vector &rule_data, base_section_info &info,
    std::unordered_map<std::string, std::string> &rule_data_ids)
{
    rule_data_container processors;
    for (unsigned i = 0; i < rule_data.size(); ++i) {
        ddwaf::parameter object = rule_data[i];
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
                    DDWAF_DEBUG("Failed to process rule data id '%s", id.c_str());
                    info.add_failed(id, "failed to infer processor");
                    continue;
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
                DDWAF_WARN("Processor %s doesn't support dynamic rule data", operation.data());
                info.add_failed(id,
                    "processor " + std::string(operation) + " doesn't support dynamic rule data");
                continue;
            }

            DDWAF_DEBUG("Parsed rule data %s", id.c_str());
            info.add_loaded(id);
            processors.emplace(std::move(id), std::move(processor));
        } catch (const ddwaf::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }

            DDWAF_ERROR("Failed to parse data id '%s': %s", id.c_str(), e.what());
            info.add_failed(id, e.what());
        }
    }

    return processors;
}

override_spec_container parse_overrides(parameter::vector &override_array, base_section_info &info)
{
    override_spec_container overrides;

    for (unsigned i = 0; i < override_array.size(); ++i) {
        auto id = index_to_id(i);
        const auto &node_param = override_array[i];
        auto node = static_cast<parameter::map>(node_param);
        try {
            auto [spec, type] = parse_override(node);
            if (type == target_type::id) {
                overrides.by_ids.emplace_back(std::move(spec));
            } else if (type == target_type::tags) {
                overrides.by_tags.emplace_back(std::move(spec));
            } else {
                // This code is likely unreachable
                DDWAF_WARN("Rule override with no targets");
                info.add_failed(id, "rule override with no targets");
                continue;
            }
            DDWAF_DEBUG("Parsed override %s", id.c_str());
            info.add_loaded(id);
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse rule override: %s", e.what());
            info.add_failed(id, e.what());
        }
    }

    return overrides;
}

filter_spec_container parse_filters(
    parameter::vector &filter_array, base_section_info &info, const object_limits &limits)
{
    filter_spec_container filters;
    for (unsigned i = 0; i < filter_array.size(); i++) {
        const auto &node_param = filter_array[i];
        auto node = static_cast<parameter::map>(node_param);
        std::string id;
        try {
            id = at<std::string>(node, "id");
            if (filters.ids.find(id) != filters.ids.end()) {
                DDWAF_WARN("Duplicate filter: %s", id.c_str());
                info.add_failed(id, "duplicate filter");
                continue;
            }

            if (node.find("inputs") != node.end()) {
                auto filter = parse_input_filter(node, limits);
                filters.ids.emplace(id);
                filters.input_filters.emplace(id, std::move(filter));
            } else {
                auto filter = parse_rule_filter(node, limits);
                filters.ids.emplace(id);
                filters.rule_filters.emplace(id, std::move(filter));
            }
            DDWAF_DEBUG("Parsed exclusion filter %s", id.c_str());
            info.add_loaded(id);
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse filter '%s': %s", id.c_str(), e.what());
            info.add_failed(id, e.what());
        }
    }

    return filters;
}

preprocessor_container parse_preprocessors(
    parameter::vector &preprocessor_array, base_section_info &info, const object_limits &limits)
{
    preprocessor_container preprocessors;

    for (unsigned i = 0; i < preprocessor_array.size(); i++) {
        const auto &node_param = preprocessor_array[i];
        auto node = static_cast<parameter::map>(node_param);
        std::string id;
        try {
            id = at<std::string>(node, "id");
            if (preprocessors.find(id) != preprocessors.end()) {
                DDWAF_WARN("Duplicate preprocessor: %s", id.c_str());
                info.add_failed(id, "duplicate preprocessor");
                continue;
            }

            std::unique_ptr<generator::base> generator;
            auto generator_id = at<std::string>(node, "generator");
            if (generator_id == "extract_schema") {
                generator = std::make_unique<generator::extract_schema>(limits);
            } else {
                DDWAF_WARN("Unknown generator: %s", generator_id.c_str());
                info.add_failed(id, "unknown generator" + generator_id);
                continue;
            }

            std::vector<condition::ptr> conditions;
            auto conditions_array = at<parameter::vector>(node, "conditions", {});
            if (!conditions_array.empty()) {
                conditions.reserve(conditions_array.size());

                for (const auto &cond : conditions_array) {
                    conditions.push_back(
                        parse_simplified_condition(static_cast<parameter::map>(cond), limits));
                }
            }

            auto params = at<parameter::map>(node, "parameters");
            auto mappings_vec = at<parameter::vector>(params, "mappings");
            auto mappings = parse_preprocessor_mappings(mappings_vec);

            DDWAF_DEBUG("Parsed preprocessor %s", id.c_str());
            auto preproc = std::make_shared<preprocessor>(preprocessor{std::move(id),
                std::move(generator), std::move(conditions), std::move(mappings),
                at<bool>(node, "evaluate", true), at<bool>(node, "output", false)});

            preprocessors.emplace(preproc->get_id(), preproc);

            info.add_loaded(preproc->get_id());
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse preprocessor '%s': %s", id.c_str(), e.what());
            info.add_failed(id, e.what());
        }
    }
    return preprocessors;
}

} // namespace ddwaf::parser::v2
