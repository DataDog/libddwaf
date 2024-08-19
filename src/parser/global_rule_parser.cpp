// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/common.hpp"
#include "parser/parser.hpp"
#include "parser/specification.hpp"
#include "rule/threshold_rule.hpp"

namespace ddwaf::parser::v2 {

namespace {
std::unique_ptr<base_threshold_rule> parse_indexed_threshold_rule(
    std::string id, parameter::map &rule, const object_limits &limits)
{
    auto conditions_array = at<parameter::vector>(rule, "conditions", {});

    address_container addresses;
    auto expr = parse_simplified_expression(conditions_array, addresses, limits);
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

    auto criteria_map = at<parameter::map>(rule, "criteria");
    indexed_threshold_rule::evaluation_criteria criteria;
    criteria.threshold = at<uint64_t>(criteria_map, "threshold");
    criteria.period = std::chrono::milliseconds(at<uint64_t>(criteria_map, "period"));

    auto filter_map = at<parameter::map>(rule, "filter");

    auto input_map = at<parameter::map>(filter_map, "input");
    criteria.filter.name = at<std::string>(input_map, "address");
    criteria.filter.target = get_target_index(criteria.filter.name);

    if (filter_map.contains("operator")) {
        auto operator_name = at<std::string_view>(filter_map, "operator");
        auto params = at<parameter::map>(filter_map, "parameters");

        auto [data_id, matcher] = parse_matcher(operator_name, params);
        if (!data_id.empty()) {
            throw ddwaf::parsing_error("unsupported: global rule filter with data ID");
        }

        criteria.filter.matcher = std::move(matcher);
    }

    return std::make_unique<indexed_threshold_rule>(std::move(id), at<std::string>(rule, "name"),
        std::move(tags), std::move(expr), std::move(criteria),
        at<std::vector<std::string>>(rule, "on_match", {}), at<bool>(rule, "enabled", true));
}

std::unique_ptr<base_threshold_rule> parse_threshold_rule(
    std::string id, parameter::map &rule, const object_limits &limits)
{
    auto conditions_array = at<parameter::vector>(rule, "conditions", {});

    address_container addresses;
    auto expr = parse_simplified_expression(conditions_array, addresses, limits);
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

    auto criteria_map = at<parameter::map>(rule, "criteria");
    threshold_rule::evaluation_criteria criteria;
    criteria.threshold = at<uint64_t>(criteria_map, "threshold");
    criteria.period = std::chrono::milliseconds(at<uint64_t>(criteria_map, "period"));

    return std::make_unique<threshold_rule>(std::move(id), at<std::string>(rule, "name"),
        std::move(tags), std::move(expr), criteria,
        at<std::vector<std::string>>(rule, "on_match", {}), at<bool>(rule, "enabled", true));
}

std::unique_ptr<base_threshold_rule> parse_global_rule(
    std::string id, parameter::map &rule, const object_limits &limits)
{
    if (rule.contains("filter")) {
        return parse_indexed_threshold_rule(std::move(id), rule, limits);
    }
    return parse_threshold_rule(std::move(id), rule, limits);
}
} // namespace

std::shared_ptr<global_context> parse_global_rules(
    parameter::vector &rule_array, base_section_info &info, const object_limits &limits)
{
    std::vector<std::unique_ptr<base_threshold_rule>> rules;

    std::unordered_set<std::string_view> ids;
    for (unsigned i = 0; i < rule_array.size(); ++i) {
        const auto &rule_param = rule_array[i];
        auto rule_map = static_cast<parameter::map>(rule_param);
        std::string id;
        try {
            address_container addresses;
            id = at<std::string>(rule_map, "id");
            if (ids.find(id) != ids.end()) {
                DDWAF_WARN("Duplicate global rule {}", id);
                info.add_failed(id, "duplicate rule");
                continue;
            }

            auto rule = parse_global_rule(id, rule_map, limits);
            DDWAF_DEBUG("Parsed global rule {}", id);
            info.add_loaded(id);
            add_addresses_to_info(addresses, info);

            rules.emplace_back(std::move(rule));
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse rule '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }

    return std::make_shared<global_context>(std::move(rules));
}

} // namespace ddwaf::parser::v2
