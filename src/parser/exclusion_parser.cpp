// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "condition/base.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "exclusion/object_filter.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"
#include "parser/specification.hpp"
#include "semver.hpp"
#include "target_address.hpp"
#include "utils.hpp"
#include "version.hpp"

namespace ddwaf::parser::v2 {

namespace {

input_filter_spec parse_input_filter(const parameter::map &filter, address_container &addresses,
    std::unordered_map<std::string, std::string> &filter_data_ids, const object_limits &limits)
{
    // Check for conditions first
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    auto expr = parse_expression(
        conditions_array, filter_data_ids, data_source::values, {}, addresses, limits);

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

        addresses.optional.emplace(address);
        obj_filter->insert(target, std::move(address), key_path);
    }

    return {std::move(expr), std::move(obj_filter), std::move(rules_target)};
}

rule_filter_spec parse_rule_filter(const parameter::map &filter, address_container &addresses,
    std::unordered_map<std::string, std::string> &filter_data_ids, const object_limits &limits)
{
    // Check for conditions first
    auto conditions_array = at<parameter::vector>(filter, "conditions", {});
    auto expr = parse_expression(
        conditions_array, filter_data_ids, data_source::values, {}, addresses, limits);

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
    std::string on_match_id;
    if (on_match_str == "bypass") {
        on_match = exclusion::filter_mode::bypass;
    } else if (on_match_str == "monitor") {
        on_match = exclusion::filter_mode::monitor;
    } else if (!on_match_str.empty()) {
        on_match = exclusion::filter_mode::custom;
        on_match_id = on_match_str;
    } else {
        throw ddwaf::parsing_error("empty on_match value");
    }

    if (expr->empty() && rules_target.empty()) {
        throw ddwaf::parsing_error("empty exclusion filter");
    }

    return {std::move(expr), std::move(rules_target), on_match, std::move(on_match_id)};
}

} // namespace

filter_spec_container parse_filters(parameter::vector &filter_array, base_section_info &info,
    std::unordered_map<std::string, std::string> &filter_data_ids, const object_limits &limits)
{
    filter_spec_container filters;
    for (unsigned i = 0; i < filter_array.size(); i++) {
        const auto &node_param = filter_array[i];
        auto node = static_cast<parameter::map>(node_param);
        std::string id;
        try {
            address_container addresses;
            id = at<std::string>(node, "id");
            if (filters.ids.find(id) != filters.ids.end()) {
                DDWAF_WARN("Duplicate filter: {}", id);
                info.add_failed(id, "duplicate filter");
                continue;
            }

            // Check version compatibility and fail without diagnostic
            auto min_version{at<semantic_version>(node, "min_version", semantic_version::min())};
            auto max_version{at<semantic_version>(node, "max_version", semantic_version::max())};
            if (min_version > current_version || max_version < current_version) {
                DDWAF_DEBUG("Skipping filter '{}': version required between [{}, {}], current {}",
                    id, min_version, max_version, current_version);
                info.add_skipped(id);
                continue;
            }

            if (node.find("inputs") != node.end()) {
                auto filter = parse_input_filter(node, addresses, filter_data_ids, limits);
                filters.ids.emplace(id);
                filters.input_filters.emplace(id, std::move(filter));
            } else {
                auto filter = parse_rule_filter(node, addresses, filter_data_ids, limits);
                filters.ids.emplace(id);
                filters.rule_filters.emplace(id, std::move(filter));
            }
            DDWAF_DEBUG("Parsed exclusion filter {}", id);

            info.add_loaded(id);
            add_addresses_to_info(addresses, info);
        } catch (const unsupported_operator_version &e) {
            DDWAF_WARN("Skipping filter '{}': {}", id, e.what());
            info.add_skipped(id);
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse filter '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }

    return filters;
}

} // namespace ddwaf::parser::v2
