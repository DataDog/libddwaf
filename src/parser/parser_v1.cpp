// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <log.hpp>
#include <operation/is_sqli.hpp>
#include <operation/is_xss.hpp>
#include <operation/phrase_match.hpp>
#include <operation/regex_match.hpp>
#include <parameter.hpp>
#include <parser/common.hpp>
#include <parser/parser.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

using ddwaf::operation::base;

namespace ddwaf::parser::v1 {

namespace {

expression::ptr parse_expression(parameter::vector &conditions_array,
    const std::vector<transformer_id> &transformers, ddwaf::object_limits limits)
{
    expression_builder builder(conditions_array.size(), limits);
    for (const auto &cond_param : conditions_array) {
        auto cond = static_cast<parameter::map>(cond_param);

        builder.start_condition();

        auto operation = at<std::string_view>(cond, "operation");
        auto params = at<parameter::map>(cond, "parameters");

        parameter::map options;
        std::shared_ptr<base> processor;
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

            processor = std::make_shared<operation::phrase_match>(patterns, lengths);
        } else if (operation == "match_regex") {
            auto regex = at<std::string>(params, "regex");
            options = at<parameter::map>(params, "options", options);

            auto case_sensitive = at<bool>(options, "case_sensitive", false);
            auto min_length = at<int64_t>(options, "min_length", 0);
            if (min_length < 0) {
                throw ddwaf::parsing_error("min_length is a negative number");
            }

            processor = std::make_shared<operation::regex_match>(regex, min_length, case_sensitive);
        } else if (operation == "is_xss") {
            processor = std::make_shared<operation::is_xss>();
        } else if (operation == "is_sqli") {
            processor = std::make_shared<operation::is_sqli>();
        } else {
            throw ddwaf::parsing_error("unknown processor: " + std::string(operation));
        }
        builder.set_processor(std::move(processor));

        auto inputs = at<parameter::vector>(params, "inputs");
        for (const auto &input_param : inputs) {
            auto input = static_cast<std::string>(input_param);
            if (input.empty()) {
                throw ddwaf::parsing_error("empty address");
            }

            std::string root;
            std::vector<std::string> key_path;
            size_t pos = input.find(':', 0);
            if (pos == std::string::npos || pos + 1 >= input.size()) {
                root = input;
            } else {
                root = input.substr(0, pos);
                key_path.emplace_back(input.substr(pos + 1, input.size()));
            }

            builder.add_target(std::move(root), std::move(key_path), transformers);
        }
    }

    return builder.build();
}

void parseRule(parameter::map &rule, base_section_info &info,
    std::unordered_set<std::string_view> &rule_ids, ddwaf::ruleset &rs, ddwaf::object_limits limits)
{
    auto id = at<std::string>(rule, "id");
    if (rule_ids.find(id) != rule_ids.end()) {
        DDWAF_WARN("duplicate rule %s", id.c_str());
        info.add_failed(id, "duplicate rule");
        return;
    }

    try {
        std::vector<transformer_id> rule_transformers;
        auto transformers = at<parameter::vector>(rule, "transformers", parameter::vector());
        for (const auto &transformer_param : transformers) {
            auto transformer = static_cast<std::string_view>(transformer_param);
            auto id = transformer_from_string(transformer);
            if (!id.has_value()) {
                throw ddwaf::parsing_error("invalid transformer" + std::string(transformer));
            }
            rule_transformers.emplace_back(id.value());
        }

        auto conditions_array = at<parameter::vector>(rule, "conditions");
        auto expression = parse_expression(conditions_array, rule_transformers, limits);

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

        auto rule_ptr = std::make_shared<ddwaf::rule>(
            std::string(id), at<std::string>(rule, "name"), std::move(tags), std::move(expression));

        rule_ids.emplace(rule_ptr->get_id());
        rs.insert_rule(rule_ptr);
        info.add_loaded(rule_ptr->get_id());
    } catch (const std::exception &e) {
        DDWAF_WARN("failed to parse rule '%s': %s", id.c_str(), e.what());
        info.add_failed(id, e.what());
    }
}

} // namespace

void parse(
    parameter::map &ruleset, base_ruleset_info &info, ddwaf::ruleset &rs, object_limits limits)
{
    auto rules_array = at<parameter::vector>(ruleset, "events");
    rs.rules.reserve(rules_array.size());

    auto &section = info.add_section("rules");

    std::unordered_set<std::string_view> rule_ids;
    for (unsigned i = 0; i < rules_array.size(); ++i) {
        const auto &rule_param = rules_array[i];
        try {
            auto rule = static_cast<parameter::map>(rule_param);
            parseRule(rule, section, rule_ids, rs, limits);
        } catch (const std::exception &e) {
            DDWAF_WARN("%s", e.what());
            section.add_failed("index:" + to_string<std::string>(i), e.what());
        }
    }

    if (rs.rules.empty()) {
        throw ddwaf::parsing_error("no valid rules found");
    }

    DDWAF_DEBUG("Loaded %zu rules out of %zu available in the ruleset", rs.rules.size(),
        rules_array.size());
}

} // namespace ddwaf::parser::v1
