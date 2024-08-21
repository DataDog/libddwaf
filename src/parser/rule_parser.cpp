// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/base.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"
#include "parser/specification.hpp"
#include "rule.hpp"
#include "transformer/base.hpp"
#include "utils.hpp"
#include <exception>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ddwaf::parser::v2 {

namespace {

rule_spec parse_rule(parameter::map &rule,
    std::unordered_map<std::string, std::string> &rule_data_ids, const object_limits &limits,
    rule::source_type source, address_container &addresses)
{
    std::vector<transformer_id> rule_transformers;
    auto data_source = ddwaf::data_source::values;
    auto transformers = at<parameter::vector>(rule, "transformers", {});
    if (transformers.size() > limits.max_transformers_per_address) {
        throw ddwaf::parsing_error("number of transformers beyond allowed limit");
    }

    rule_transformers = parse_transformers(transformers, data_source);

    auto conditions_array = at<parameter::vector>(rule, "conditions");
    auto expr = parse_expression(
        conditions_array, rule_data_ids, data_source, rule_transformers, addresses, limits);
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
            address_container addresses;

            id = at<std::string>(rule_map, "id");
            if (rules.find(id) != rules.end()) {
                DDWAF_WARN("Duplicate rule {}", id);
                info.add_failed(id, "duplicate rule");
                continue;
            }

            auto rule = parse_rule(rule_map, rule_data_ids, limits, source, addresses);
            DDWAF_DEBUG("Parsed rule {}", id);
            info.add_loaded(id);
            add_addresses_to_info(addresses, info);

            rules.emplace(std::move(id), std::move(rule));
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse rule '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }

    return rules;
}

} // namespace ddwaf::parser::v2
