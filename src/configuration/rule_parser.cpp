// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <exception>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "condition/base.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/expression_parser.hpp"
#include "configuration/common/transformer_parser.hpp"
#include "configuration/rule_parser.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "rule.hpp"
#include "semver.hpp"
#include "transformer/base.hpp"
#include "utils.hpp"
#include "version.hpp"

namespace ddwaf {

namespace {

rule_spec parse_rule(parameter::map &rule, const object_limits &limits,
    core_rule::source_type source, address_container &addresses)
{
    std::vector<transformer_id> rule_transformers;
    auto data_source = ddwaf::data_source::values;
    auto transformers = at<parameter::vector>(rule, "transformers", {});
    if (transformers.size() > limits.max_transformers_per_address) {
        throw ddwaf::parsing_error("number of transformers beyond allowed limit");
    }

    rule_transformers = parse_transformers(transformers, data_source);

    auto conditions_array = at<parameter::vector>(rule, "conditions");
    auto expr =
        parse_expression(conditions_array, data_source, rule_transformers, addresses, limits);
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

    return {.enabled = at<bool>(rule, "enabled", true),
        .source = source,
        .name = at<std::string>(rule, "name"),
        .tags = std::move(tags),
        .expr = std::move(expr),
        .actions = at<std::vector<std::string>>(rule, "on_match", {})};
}

void parse_rules(const parameter::vector &rule_array, configuration_collector &cfg,
    base_section_info &info, core_rule::source_type source, const object_limits &limits)
{
    for (unsigned i = 0; i < rule_array.size(); ++i) {
        std::string id;
        try {
            const auto &rule_param = rule_array[i];
            auto node = static_cast<parameter::map>(rule_param);

            address_container addresses;

            id = at<std::string>(node, "id");
            if (cfg.contains_rule(id)) {
                DDWAF_WARN("Duplicate rule {}", id);
                info.add_failed(id, "duplicate rule");
                continue;
            }

            // Check version compatibility and fail without diagnostic
            auto min_version{at<semantic_version>(node, "min_version", semantic_version::min())};
            auto max_version{at<semantic_version>(node, "max_version", semantic_version::max())};
            if (min_version > current_version || max_version < current_version) {
                DDWAF_DEBUG("Skipping rule '{}': version required between [{}, {}], current {}", id,
                    min_version, max_version, current_version);
                info.add_skipped(id);
                continue;
            }

            auto rule = parse_rule(node, limits, source, addresses);

            DDWAF_DEBUG("Parsed rule {}", id);
            info.add_loaded(id);
            add_addresses_to_info(addresses, info);
            cfg.emplace_rule(std::move(id), std::move(rule));
        } catch (const unsupported_operator_version &e) {
            DDWAF_WARN("Skipping rule '{}': {}", id, e.what());
            info.add_skipped(id);
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse rule '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }
}

} // namespace

void parse_base_rules(const parameter::vector &rule_array, configuration_collector &cfg,
    base_section_info &info, const object_limits &limits)
{
    parse_rules(rule_array, cfg, info, core_rule::source_type::base, limits);
}

void parse_user_rules(const parameter::vector &rule_array, configuration_collector &cfg,
    base_section_info &info, const object_limits &limits)
{
    parse_rules(rule_array, cfg, info, core_rule::source_type::user, limits);
}
} // namespace ddwaf
