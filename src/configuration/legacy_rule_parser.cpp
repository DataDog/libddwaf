// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "condition/base.hpp"
#include "condition/scalar_condition.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/transformer_parser.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "matcher/is_sqli.hpp"
#include "matcher/is_xss.hpp"
#include "matcher/phrase_match.hpp"
#include "matcher/regex_match.hpp"
#include "parameter.hpp"
#include "rule.hpp"
#include "target_address.hpp"
#include "transformer/base.hpp"
#include "utils.hpp"

namespace ddwaf {

namespace {

std::shared_ptr<expression> parse_expression(parameter::vector &conditions_array,
    const std::vector<transformer_id> &transformers, ddwaf::object_limits limits)
{
    std::vector<std::unique_ptr<base_condition>> conditions;

    for (const auto &cond_param : conditions_array) {
        auto cond = static_cast<parameter::map>(cond_param);

        auto matcher_name = at<std::string_view>(cond, "operation");
        auto params = at<parameter::map>(cond, "parameters");

        parameter::map options;
        std::unique_ptr<matcher::base> matcher;
        if (matcher_name == "phrase_match") {
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
        } else if (matcher_name == "match_regex") {
            auto regex = at<std::string>(params, "regex");
            options = at<parameter::map>(params, "options", options);

            auto case_sensitive = at<bool>(options, "case_sensitive", false);
            auto min_length = at<int64_t>(options, "min_length", 0);
            if (min_length < 0) {
                throw ddwaf::parsing_error("min_length is a negative number");
            }

            matcher = std::make_unique<matcher::regex_match>(regex, min_length, case_sensitive);
        } else if (matcher_name == "is_xss") {
            matcher = std::make_unique<matcher::is_xss>();
        } else if (matcher_name == "is_sqli") {
            matcher = std::make_unique<matcher::is_sqli>();
        } else {
            throw ddwaf::parsing_error("unknown matcher: " + std::string(matcher_name));
        }

        std::vector<condition_parameter> definitions;
        definitions.emplace_back();
        condition_parameter &def = definitions.back();

        auto inputs = at<parameter::vector>(params, "inputs");
        for (const auto &input_param : inputs) {
            auto input = static_cast<std::string>(input_param);
            if (input.empty()) {
                throw ddwaf::parsing_error("empty address");
            }

            std::string root;
            std::vector<std::string> key_path;
            const size_t pos = input.find(':', 0);
            if (pos == std::string::npos || pos + 1 >= input.size()) {
                root = input;
            } else {
                root = input.substr(0, pos);
                key_path.emplace_back(input.substr(pos + 1, input.size()));
            }

            def.targets.emplace_back(condition_target{root, get_target_index(root),
                std::move(key_path), transformers, data_source::values});
        }

        conditions.emplace_back(std::make_unique<scalar_condition>(
            std::move(matcher), std::string{}, std::move(definitions), limits));
    }

    return std::make_shared<expression>(std::move(conditions));
}

} // namespace

bool parse_legacy_rules(const parameter::vector &rule_array, configuration_collector &cfg,
    base_section_info &info, object_limits limits)
{
    bool rules_parsed = false;
    for (unsigned i = 0; i < rule_array.size(); ++i) {
        std::string id;
        try {
            const auto &rule_param = rule_array[i];
            auto node = static_cast<parameter::map>(rule_param);

            id = at<std::string>(node, "id");
            if (cfg.contains_rule(id)) {
                DDWAF_WARN("Duplicate rule {}", id);
                info.add_failed(id, "duplicate rule");
                continue;
            }

            std::vector<transformer_id> rule_transformers;
            auto transformers = at<parameter::vector>(node, "transformers", parameter::vector());
            if (transformers.size() > limits.max_transformers_per_address) {
                throw ddwaf::parsing_error("number of transformers beyond allowed limit");
            }

            for (const auto &transformer_param : transformers) {
                auto transformer = static_cast<std::string_view>(transformer_param);
                auto id = transformer_from_string(transformer);
                if (!id.has_value()) {
                    throw ddwaf::parsing_error("invalid transformer" + std::string(transformer));
                }
                rule_transformers.emplace_back(id.value());
            }

            auto conditions_array = at<parameter::vector>(node, "conditions");
            auto expression = parse_expression(conditions_array, rule_transformers, limits);

            std::unordered_map<std::string, std::string> tags;
            for (auto &[key, value] : at<parameter::map>(node, "tags")) {
                try {
                    tags.emplace(key, std::string(value));
                } catch (const bad_cast &e) {
                    throw invalid_type(std::string(key), e);
                }
            }

            if (tags.find("type") == tags.end()) {
                throw ddwaf::parsing_error("missing key 'type'");
            }

            rule_spec spec{std::move(id), true, core_rule::source_type::base,
                at<std::string>(node, "name"), std::move(tags), std::move(expression), {}};

            DDWAF_DEBUG("Parsed rule {}", id);
            rules_parsed = true;
            info.add_loaded(spec.id);
            cfg.emplace_rule(spec.id, std::move(spec));
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse rule '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }

    return rules_parsed;
}

} // namespace ddwaf
