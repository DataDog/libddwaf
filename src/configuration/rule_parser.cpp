// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <exception>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "condition/base.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/expression_parser.hpp"
#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/common/transformer_parser.hpp"
#include "configuration/rule_parser.hpp"
#include "ddwaf.h"
#include "log.hpp"
#include "rule.hpp"
#include "semver.hpp"
#include "target_address.hpp"
#include "transformer/base.hpp"
#include "utils.hpp"
#include "version.hpp"

namespace ddwaf {

namespace {

rule_spec parse_rule(raw_configuration::map &rule, core_rule::source_type source)
{
    std::vector<transformer_id> rule_transformers;
    auto data_source = ddwaf::data_source::values;
    auto transformers = at<raw_configuration::vector>(rule, "transformers", {});
    if (transformers.size() > object_limits::max_transformers_per_address) {
        throw ddwaf::parsing_error("number of transformers beyond allowed limit");
    }

    rule_transformers = parse_transformers(transformers, data_source);

    auto conditions_array = at<raw_configuration::vector>(rule, "conditions");
    auto expr = parse_expression(conditions_array, data_source, rule_transformers);
    if (expr->empty()) {
        // This is likely unreachable
        throw ddwaf::parsing_error("rule has no valid conditions");
    }

    std::unordered_map<std::string, std::string> tags;
    for (auto &[key, value] : at<raw_configuration::map>(rule, "tags")) {
        try {
            tags.emplace(key, std::string(value));
        } catch (const bad_cast &e) {
            throw invalid_type(std::string(key), e);
        }
    }

    if (tags.find("type") == tags.end()) {
        throw ddwaf::parsing_error("missing key 'type'");
    }

    auto output = at<raw_configuration::map>(rule, "output", {});
    rule_flags flags = rule_flags::none;
    if (at<bool>(output, "event", true)) {
        flags = flags | rule_flags::generate_event;
    }
    if (at<bool>(output, "keep", true)) {
        flags = flags | rule_flags::keep_outcome;
    }

    auto attr_map = at<raw_configuration::map>(output, "attributes", {});
    std::vector<rule_attribute> attributes;
    for (auto &[output, value_or_target] : attr_map) {
        rule_attribute attr_spec;
        attr_spec.output = output;

        auto value_or_target_map = static_cast<raw_configuration::map>(value_or_target);
        if (value_or_target_map.contains("value")) {
            auto value = static_cast<ddwaf_object>(value_or_target_map["value"]);
            switch (value.type) {
            case DDWAF_OBJ_STRING:
                attr_spec.input =
                    std::string{value.stringValue, static_cast<std::size_t>(value.nbEntries)};
                break;
            case DDWAF_OBJ_UNSIGNED:
                attr_spec.input = value.uintValue;
                break;
            case DDWAF_OBJ_SIGNED:
                attr_spec.input = value.intValue;
                break;
            case DDWAF_OBJ_FLOAT:
                attr_spec.input = value.f64;
                break;
            case DDWAF_OBJ_BOOL:
                attr_spec.input = value.boolean;
                break;
            default:
                throw parsing_error("invalid type for 'value', expected scalar");
            }
        } else {
            auto address = at<std::string_view>(value_or_target_map, "address");
            attr_spec.input = rule_attribute::input_target{.name = std::string{address},
                .index = get_target_index(address),
                .key_path = at<std::vector<std::string>>(value_or_target_map, "key_path", {})};
        }
    }

    return {.enabled = at<bool>(rule, "enabled", true),
        .flags = flags,
        .source = source,
        .name = at<std::string>(rule, "name"),
        .tags = std::move(tags),
        .expr = std::move(expr),
        .actions = at<std::vector<std::string>>(rule, "on_match", {}),
        .attributes = std::move(attributes)};
}

void parse_rules(const raw_configuration::vector &rule_array, configuration_collector &cfg,
    base_section_info &info, core_rule::source_type source)
{
    for (unsigned i = 0; i < rule_array.size(); ++i) {
        std::string id;
        try {
            const auto &rule_param = rule_array[i];
            auto node = static_cast<raw_configuration::map>(rule_param);

            id = at<std::string>(node, "id");
            if (cfg.contains_rule(id)) {
                DDWAF_WARN("Duplicate rule {}", id);
                info.add_failed(id, parser_error_severity::error, "duplicate rule");
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

            auto rule = parse_rule(node, source);
            if (!contains(rule.flags, rule_flags::generate_event) && rule.attributes.empty()) {
                DDWAF_WARN("Rule generates no events or attributes: {}", id);
                info.add_failed(
                    id, parser_error_severity::error, "rule generate no events or attributes");
                continue;
            }

            DDWAF_DEBUG("Parsed rule {}", id);
            info.add_loaded(id);
            cfg.emplace_rule(std::move(id), std::move(rule));
        } catch (const unsupported_operator_version &e) {
            DDWAF_WARN("Skipping rule '{}': {}", id, e.what());
            info.add_skipped(id);
        } catch (const parsing_exception &e) {
            DDWAF_WARN("Failed to parse rule '{}': {}", id, e.what());
            info.add_failed(i, id, e.severity(), e.what());
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse rule '{}': {}", id, e.what());
            info.add_failed(i, id, parser_error_severity::error, e.what());
        }
    }
}

} // namespace

void parse_base_rules(const raw_configuration::vector &rule_array, configuration_collector &cfg,
    base_section_info &info)
{
    parse_rules(rule_array, cfg, info, core_rule::source_type::base);
}

void parse_user_rules(const raw_configuration::vector &rule_array, configuration_collector &cfg,
    base_section_info &info)
{
    parse_rules(rule_array, cfg, info, core_rule::source_type::user);
}
} // namespace ddwaf
