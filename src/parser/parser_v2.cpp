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
#include <matcher/equals.hpp>
#include <matcher/exact_match.hpp>
#include <matcher/ip_match.hpp>
#include <matcher/is_sqli.hpp>
#include <matcher/is_xss.hpp>
#include <matcher/phrase_match.hpp>
#include <matcher/regex_match.hpp>
#include <parameter.hpp>
#include <parser/common.hpp>
#include <parser/parser.hpp>
#include <parser/rule_data_parser.hpp>
#include <parser/specification.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace ddwaf::parser::v2 {

namespace {

std::pair<std::string, matcher::base::unique_ptr> parse_matcher(
    std::string_view name, const parameter::map &params)
{
    parameter::map options;
    std::unique_ptr<matcher::base> matcher;
    std::string rule_data_id;

    if (name == "phrase_match") {
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

        matcher = std::make_unique<matcher::phrase_match>(patterns, lengths);
    } else if (name == "match_regex") {
        auto regex = at<std::string>(params, "regex");
        options = at<parameter::map>(params, "options", options);

        auto case_sensitive = at<bool>(options, "case_sensitive", false);
        auto min_length = at<int64_t>(options, "min_length", 0);
        if (min_length < 0) {
            throw ddwaf::parsing_error("min_length is a negative number");
        }

        matcher = std::make_unique<matcher::regex_match>(regex, min_length, case_sensitive);
    } else if (name == "is_xss") {
        matcher = std::make_unique<matcher::is_xss>();
    } else if (name == "is_sqli") {
        matcher = std::make_unique<matcher::is_sqli>();
    } else if (name == "ip_match") {
        auto it = params.find("list");
        if (it == params.end()) {
            rule_data_id = at<std::string>(params, "data");
        } else {
            matcher = std::make_unique<matcher::ip_match>(
                static_cast<std::vector<std::string_view>>(it->second));
        }
    } else if (name == "exact_match") {
        auto it = params.find("list");
        if (it == params.end()) {
            rule_data_id = at<std::string>(params, "data");
        } else {
            matcher = std::make_unique<matcher::exact_match>(
                static_cast<std::vector<std::string>>(it->second));
        }
    } else if (name == "equals") {
        auto value_type = at<std::string>(params, "type");
        if (value_type == "string") {
            auto value = at<std::string>(params, "value");
            matcher = std::make_unique<matcher::equals<std::string>>(std::move(value));
        } else if (value_type == "boolean") {
            auto value = at<bool>(params, "value");
            matcher = std::make_unique<matcher::equals<bool>>(value);
        } else if (value_type == "unsigned") {
            auto value = at<uint64_t>(params, "value");
            matcher = std::make_unique<matcher::equals<uint64_t>>(value);
        } else if (value_type == "signed") {
            auto value = at<int64_t>(params, "value");
            matcher = std::make_unique<matcher::equals<int64_t>>(value);
        } else if (value_type == "float") {
            auto value = at<double>(params, "value");
            auto delta = at<double>(params, "delta", 0.01);
            matcher = std::make_unique<matcher::equals<double>>(value, delta);
        } else {
            throw ddwaf::parsing_error("invalid type for matcher equals" + value_type);
        }
    } else {
        throw ddwaf::parsing_error("unknown matcher: " + std::string(name));
    }

    return {std::move(rule_data_id), std::move(matcher)};
}

std::vector<transformer_id> parse_transformers(
    const parameter::vector &root, expression::data_source &source)
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
            source = ddwaf::expression::data_source::keys;
        } else if (transformer == "values_only") {
            source = ddwaf::expression::data_source::values;
        } else {
            throw ddwaf::parsing_error("invalid transformer " + std::string(transformer));
        }
    }
    return transformers;
}

expression::ptr parse_expression(const parameter::vector &conditions_array,
    std::unordered_map<std::string, std::string> &rule_data_ids, expression::data_source source,
    const std::vector<transformer_id> &transformers, const object_limits &limits)
{
    expression_builder builder(conditions_array.size(), limits);

    for (const auto &cond_param : conditions_array) {
        auto root = static_cast<parameter::map>(cond_param);

        builder.start_condition();

        auto matcher_name = at<std::string_view>(root, "operator");
        auto params = at<parameter::map>(root, "parameters");

        auto [rule_data_id, matcher] = parse_matcher(matcher_name, params);
        builder.set_data_id(rule_data_id);
        builder.set_matcher(std::move(matcher));
        if (!matcher && !rule_data_id.empty()) {
            rule_data_ids.emplace(rule_data_id, matcher_name);
        }

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

            auto it = input.find("transformers");
            if (it == input.end()) {
                builder.add_target(address, std::move(kp), transformers, source);
            } else {
                auto input_transformers = static_cast<parameter::vector>(it->second);
                source = expression::data_source::values;
                auto new_transformers = parse_transformers(input_transformers, source);
                builder.add_target(address, std::move(kp), std::move(new_transformers), source);
            }
        }
    }

    return builder.build();
}

rule_spec parse_rule(parameter::map &rule,
    std::unordered_map<std::string, std::string> &rule_data_ids, const object_limits &limits,
    rule::source_type source)
{
    std::vector<transformer_id> rule_transformers;
    auto data_source = ddwaf::expression::data_source::values;
    auto transformers = at<parameter::vector>(rule, "transformers", {});
    rule_transformers = parse_transformers(transformers, data_source);

    auto conditions_array = at<parameter::vector>(rule, "conditions");
    auto expr =
        parse_expression(conditions_array, rule_data_ids, data_source, rule_transformers, limits);
    if (expr->empty()) {
        // This is likely unreachable
        throw ddwaf::parsing_error("rule has no valid conditions");
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
        std::move(expr), at<std::vector<std::string>>(rule, "on_match", {})};
}

reference_spec parse_reference(const parameter::map &target)
{
    auto ref_id = at<std::string>(target, "rule_id", {});
    if (!ref_id.empty()) {
        return {reference_type::id, std::move(ref_id), {}};
    }

    ref_id = at<std::string>(target, "id", {});
    if (!ref_id.empty()) {
        return {reference_type::id, std::move(ref_id), {}};
    }

    auto tag_map = at<parameter::map>(target, "tags", {});
    if (!tag_map.empty()) {
        std::unordered_map<std::string, std::string> tags;
        for (auto &[key, value] : tag_map) { tags.emplace(key, value); }

        return {reference_type::tags, {}, std::move(tags)};
    }

    return {reference_type::none, {}, {}};
}

std::pair<override_spec, reference_type> parse_override(const parameter::map &node)
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

    reference_type type = reference_type::none;

    auto rules_target_array = at<parameter::vector>(node, "rules_target", {});
    if (!rules_target_array.empty()) {
        current.targets.reserve(rules_target_array.size());

        for (const auto &target : rules_target_array) {
            auto target_spec = parse_reference(static_cast<parameter::map>(target));
            if (type == reference_type::none) {
                type = target_spec.type;
            } else if (type != target_spec.type) {
                throw ddwaf::parsing_error("rule override targets rules and tags");
            }

            current.targets.emplace_back(std::move(target_spec));
        }
    } else {
        // Since the rules_target array is empty, the ID is mandatory
        current.targets.emplace_back(
            reference_spec{reference_type::id, at<std::string>(node, "id"), {}});
        type = reference_type::id;
    }

    if (!current.actions.has_value() && !current.enabled.has_value()) {
        throw ddwaf::parsing_error("rule override without side-effects");
    }

    return {current, type};
}

expression::ptr parse_simplified_expression(
    const parameter::vector &conditions_array, const object_limits &limits)
{
    expression_builder builder(conditions_array.size(), limits);

    for (const auto &cond_param : conditions_array) {
        auto root = static_cast<parameter::map>(cond_param);

        builder.start_condition();

        auto matcher_name = at<std::string_view>(root, "operator");
        auto params = at<parameter::map>(root, "parameters");

        auto [rule_data_id, matcher] = parse_matcher(matcher_name, params);
        if (!rule_data_id.empty()) {
            throw ddwaf::parsing_error("dynamic data on filter condition");
        }

        builder.set_matcher(std::move(matcher));

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

            auto source = expression::data_source::values;
            auto it = input.find("transformers");
            if (it == input.end()) {
                builder.add_target(address, std::move(kp), {}, source);
            } else {
                auto input_transformers = static_cast<parameter::vector>(it->second);
                source = expression::data_source::values;
                auto new_transformers = parse_transformers(input_transformers, source);
                builder.add_target(address, std::move(kp), std::move(new_transformers), source);
            }
        }
    }

    return builder.build();
}

input_filter_spec parse_input_filter(const parameter::map &filter, const object_limits &limits)
{
    // Check for conditions first
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    auto expr = parse_simplified_expression(conditions_array, limits);

    std::vector<reference_spec> rules_target;
    auto rules_target_array = at<parameter::vector>(filter, "rules_target", {});
    if (!rules_target_array.empty()) {
        rules_target.reserve(rules_target_array.size());

        for (const auto &target : rules_target_array) {
            rules_target.emplace_back(parse_reference(static_cast<parameter::map>(target)));
        }
    }

    auto obj_filter = std::make_shared<exclusion::object_filter>(limits);
    auto inputs_array = at<parameter::vector>(filter, "inputs");

    // TODO: add empty method to object filter and check after
    if (expr->empty() && inputs_array.empty() && rules_target.empty()) {
        throw ddwaf::parsing_error("empty exclusion filter");
    }

    for (const auto &input_param : inputs_array) {
        auto input_map = static_cast<parameter::map>(input_param);
        auto address = at<std::string>(input_map, "address");

        auto target = get_target_index(address);
        auto key_path = at<std::vector<std::string_view>>(input_map, "key_path", {});

        obj_filter->insert(target, std::move(address), key_path);
    }

    return {std::move(expr), std::move(obj_filter), std::move(rules_target)};
}

rule_filter_spec parse_rule_filter(const parameter::map &filter, const object_limits &limits)
{
    // Check for conditions first
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    auto expr = parse_simplified_expression(conditions_array, limits);

    std::vector<reference_spec> rules_target;
    auto rules_target_array = at<parameter::vector>(filter, "rules_target", {});
    if (!rules_target_array.empty()) {
        rules_target.reserve(rules_target_array.size());

        for (const auto &target : rules_target_array) {
            rules_target.emplace_back(parse_reference(static_cast<parameter::map>(target)));
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

    if (expr->empty() && rules_target.empty()) {
        throw ddwaf::parsing_error("empty exclusion filter");
    }

    return {std::move(expr), std::move(rules_target), on_match};
}

std::vector<processor::target_mapping> parse_processor_mappings(const parameter::vector &root)
{
    if (root.empty()) {
        throw ddwaf::parsing_error("empty mappings");
    }

    std::vector<processor::target_mapping> mappings;
    for (const auto &node : root) {
        auto mapping = static_cast<parameter::map>(node);

        // TODO support n:1 mappings and key paths
        auto inputs = at<parameter::vector>(mapping, "inputs");
        if (inputs.empty()) {
            throw ddwaf::parsing_error("empty processor input mapping");
        }

        auto input = static_cast<parameter::map>(inputs[0]);
        auto input_address = at<std::string_view>(input, "address");
        auto output = at<std::string>(mapping, "output");

        mappings.emplace_back(processor::target_mapping{
            get_target_index(input_address), get_target_index(output), std::move(output)});
    }

    return mappings;
}

matcher::base::unique_ptr parse_scanner_matcher(const parameter::map &root)
{
    auto matcher_name = at<std::string_view>(root, "operator");
    auto matcher_params = at<parameter::map>(root, "parameters");

    auto [rule_data_id, matcher] = parse_matcher(matcher_name, matcher_params);
    if (!rule_data_id.empty()) {
        throw ddwaf::parsing_error("dynamic data on scanner condition");
    }

    return std::move(matcher);
}

std::string index_to_id(unsigned idx) { return "index:" + to_string<std::string>(idx); }

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
    rule_data_container matchers;
    for (unsigned i = 0; i < rule_data.size(); ++i) {
        const ddwaf::parameter object = rule_data[i];
        std::string id;
        try {
            const auto entry = static_cast<ddwaf::parameter::map>(object);

            id = at<std::string>(entry, "id");

            auto type = at<std::string_view>(entry, "type");
            auto data = at<parameter>(entry, "data");

            std::string_view matcher_name;
            auto it = rule_data_ids.find(id);
            if (it == rule_data_ids.end()) {
                // Infer matcher from data type
                if (type == "ip_with_expiration") {
                    matcher_name = "ip_match";
                } else if (type == "data_with_expiration") {
                    matcher_name = "exact_match";
                } else {
                    DDWAF_DEBUG("Failed to process rule data id '%s", id.c_str());
                    info.add_failed(id, "failed to infer matcher");
                    continue;
                }
            } else {
                matcher_name = it->second;
            }

            matcher::base::shared_ptr matcher;
            if (matcher_name == "ip_match") {
                using rule_data_type = matcher::ip_match::rule_data_type;
                auto parsed_data = parser::parse_rule_data<rule_data_type>(type, data);
                matcher = std::make_shared<matcher::ip_match>(parsed_data);
            } else if (matcher_name == "exact_match") {
                using rule_data_type = matcher::exact_match::rule_data_type;
                auto parsed_data = parser::parse_rule_data<rule_data_type>(type, data);
                matcher = std::make_shared<matcher::exact_match>(parsed_data);
            } else {
                DDWAF_WARN("Matcher %s doesn't support dynamic rule data", matcher_name.data());
                info.add_failed(id,
                    "matcher " + std::string(matcher_name) + " doesn't support dynamic rule data");
                continue;
            }

            DDWAF_DEBUG("Parsed rule data %s", id.c_str());
            info.add_loaded(id);
            matchers.emplace(std::move(id), std::move(matcher));
        } catch (const ddwaf::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }

            DDWAF_ERROR("Failed to parse data id '%s': %s", id.c_str(), e.what());
            info.add_failed(id, e.what());
        }
    }

    return matchers;
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
            if (type == reference_type::id) {
                overrides.by_ids.emplace_back(std::move(spec));
            } else if (type == reference_type::tags) {
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

processor_container parse_processors(
    parameter::vector &processor_array, base_section_info &info, const object_limits &limits)
{
    processor_container processors;
    std::unordered_set<std::string_view> known_processors;

    for (unsigned i = 0; i < processor_array.size(); i++) {
        const auto &node_param = processor_array[i];
        auto node = static_cast<parameter::map>(node_param);
        std::string id;
        try {
            id = at<std::string>(node, "id");
            if (known_processors.find(id) != known_processors.end()) {
                DDWAF_WARN("Duplicate processor: %s", id.c_str());
                info.add_failed(id, "duplicate processor");
                continue;
            }

            std::shared_ptr<generator::base> generator;
            auto generator_id = at<std::string>(node, "generator");
            if (generator_id == "extract_schema") {
                generator = std::make_shared<generator::extract_schema>();
            } else {
                DDWAF_WARN("Unknown generator: %s", generator_id.c_str());
                info.add_failed(id, "unknown generator '" + generator_id + "'");
                continue;
            }

            auto conditions_array = at<parameter::vector>(node, "conditions", {});
            auto expr = parse_simplified_expression(conditions_array, limits);

            auto params = at<parameter::map>(node, "parameters");
            auto mappings_vec = at<parameter::vector>(params, "mappings");
            auto mappings = parse_processor_mappings(mappings_vec);

            std::vector<reference_spec> scanners;
            auto scanners_ref_array = at<parameter::vector>(params, "scanners", {});
            if (!scanners_ref_array.empty()) {
                scanners.reserve(scanners_ref_array.size());
                for (const auto &ref : scanners_ref_array) {
                    scanners.emplace_back(parse_reference(static_cast<parameter::map>(ref)));
                }
            }

            auto eval = at<bool>(node, "evaluate", true);
            auto output = at<bool>(node, "output", false);

            if (!eval && !output) {
                DDWAF_WARN("Processor %s not used for evaluation or output", id.c_str());
                info.add_failed(id, "processor not used for evaluation or output");
                continue;
            }

            DDWAF_DEBUG("Parsed processor %s", id.c_str());
            info.add_loaded(id);
            if (eval) {
                processors.pre.emplace(
                    std::move(id), processor_spec{std::move(generator), std::move(expr),
                                       std::move(mappings), std::move(scanners), eval, output});
            } else {
                processors.post.emplace(
                    std::move(id), processor_spec{std::move(generator), std::move(expr),
                                       std::move(mappings), std::move(scanners), eval, output});
            }

        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse processor '%s': %s", id.c_str(), e.what());
            info.add_failed(id, e.what());
        }
    }
    return processors;
}

scanner_container parse_scanners(parameter::vector &scanner_array, base_section_info &info)
{
    scanner_container scanners;
    for (unsigned i = 0; i < scanner_array.size(); i++) {
        const auto &node_param = scanner_array[i];
        auto node = static_cast<parameter::map>(node_param);
        std::string id;
        try {
            id = at<std::string>(node, "id");
            if (scanners.find(id) != scanners.end()) {
                DDWAF_WARN("Duplicate scanner: %s", id.c_str());
                info.add_failed(id, "duplicate scanner");
                continue;
            }

            std::unordered_map<std::string, std::string> tags;
            for (auto &[key, value] : at<parameter::map>(node, "tags")) {
                try {
                    tags.emplace(key, std::string(value));
                } catch (const bad_cast &e) {
                    throw invalid_type(std::string(key), e);
                }
            }

            matcher::base::unique_ptr key_matcher{};
            matcher::base::unique_ptr value_matcher{};

            auto it = node.find("key");
            if (it != node.end()) {
                auto matcher_node = parameter::map(it->second);
                key_matcher = parse_scanner_matcher(matcher_node);
            }

            it = node.find("value");
            if (it != node.end()) {
                auto matcher_node = parameter::map(it->second);
                value_matcher = parse_scanner_matcher(matcher_node);
            }

            if (!key_matcher && !value_matcher) {
                DDWAF_WARN("Scanner %s has no key or value matcher", id.c_str());
                info.add_failed(id, "scanner has no key or value matcher");
                continue;
            }

            DDWAF_DEBUG("Parsed scanner %s", id.c_str());
            auto scnr = std::make_shared<scanner>(scanner{
                std::move(id), std::move(tags), std::move(key_matcher), std::move(value_matcher)});
            scanners.emplace(scnr->get_id(), scnr);
            info.add_loaded(scnr->get_id());
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse scanner '%s': %s", id.c_str(), e.what());
            info.add_failed(id, e.what());
        }
    }
    return scanners;
}

} // namespace ddwaf::parser::v2
