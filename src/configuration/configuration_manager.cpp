// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2024 Datadog, Inc.

#include <exception>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "configuration/actions_parser.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/configuration_manager.hpp"
#include "configuration/data_parser.hpp"
#include "configuration/exclusion_parser.hpp"
#include "configuration/legacy_rule_parser.hpp"
#include "configuration/processor_parser.hpp"
#include "configuration/rule_override_parser.hpp"
#include "configuration/rule_parser.hpp"
#include "configuration/scanner_parser.hpp"
#include "fmt/core.h"
#include "log.hpp"
#include "ruleset_info.hpp"

namespace ddwaf {

void configuration_manager::load(
    raw_configuration::map &root, configuration_collector &collector, base_ruleset_info &info)
{
    auto metadata = at<raw_configuration::map>(root, "metadata", {});
    auto rules_version = at<std::string_view>(metadata, "rules_version", {});
    if (!rules_version.empty()) {
        info.set_ruleset_version(rules_version);
    }

    auto schema_version = parse_schema_version(root);
    if (schema_version == 1) {
        // Legacy configurations with schema version 1 will only provide rules
        DDWAF_DEBUG("Parsing legacy configuration");

        auto it = root.find("events");
        if (it != root.end()) {
            auto &section = info.add_section("rules");
            try {
                auto rules = static_cast<raw_configuration::vector>(it->second);
                if (!rules.empty()) {
                    parse_legacy_rules(rules, collector, section, limits_);
                }
            } catch (const std::exception &e) {
                DDWAF_WARN("Failed to parse rules: {}", e.what());
                section.set_error(e.what());
            }
        }

        return;
    }

    auto it = root.find("actions");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing actions");
        auto &section = info.add_section("actions");
        try {
            auto actions = static_cast<raw_configuration::vector>(it->second);
            if (!actions.empty()) {
                parse_actions(actions, collector, section);
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse actions: {}", e.what());
            section.set_error(e.what());
        }
    }

    it = root.find("rules");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing base rules");
        auto &section = info.add_section("rules");
        try {
            auto rules = static_cast<raw_configuration::vector>(it->second);
            if (!rules.empty()) {
                parse_base_rules(rules, collector, section, limits_);
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse rules: {}", e.what());
            section.set_error(e.what());
        }
    }

    it = root.find("custom_rules");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing custom rules");
        auto &section = info.add_section("custom_rules");
        try {
            auto rules = static_cast<raw_configuration::vector>(it->second);
            if (!rules.empty()) {
                parse_user_rules(rules, collector, section, limits_);
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse custom rules: {}", e.what());
            section.set_error(e.what());
        }
    }

    it = root.find("rules_data");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing rule data");
        auto &section = info.add_section("rules_data");
        try {
            auto rules_data = static_cast<raw_configuration::vector>(it->second);
            if (!rules_data.empty()) {
                parse_rule_data(rules_data, collector, section);
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse rule data: {}", e.what());
            section.set_error(e.what());
        }
    }

    it = root.find("rules_override");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing overrides");
        auto &section = info.add_section("rules_override");
        try {
            auto overrides = static_cast<raw_configuration::vector>(it->second);
            if (!overrides.empty()) {
                parse_overrides(overrides, collector, section);
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse overrides: {}", e.what());
            section.set_error(e.what());
        }
    }

    it = root.find("exclusions");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing exclusions");
        auto &section = info.add_section("exclusions");
        try {
            auto exclusions = static_cast<raw_configuration::vector>(it->second);
            if (!exclusions.empty()) {
                parse_filters(exclusions, collector, section, limits_);
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse exclusions: {}", e.what());
            section.set_error(e.what());
        }
    }

    it = root.find("exclusion_data");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing exclusion data");
        auto &section = info.add_section("exclusion_data");
        try {
            auto exclusions_data = static_cast<raw_configuration::vector>(it->second);
            if (!exclusions_data.empty()) {
                parse_exclusion_data(exclusions_data, collector, section);
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse exclusion data: {}", e.what());
            section.set_error(e.what());
        }
    }

    it = root.find("processors");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing processors");
        auto &section = info.add_section("processors");
        try {
            auto processors = static_cast<raw_configuration::vector>(it->second);
            if (!processors.empty()) {
                parse_processors(processors, collector, section, limits_);
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse processors: {}", e.what());
            section.set_error(e.what());
        }
    }

    it = root.find("scanners");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing scanners");
        auto &section = info.add_section("scanners");
        try {
            auto scanners = static_cast<raw_configuration::vector>(it->second);
            if (!scanners.empty()) {
                parse_scanners(scanners, collector, section);
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse scanners: {}", e.what());
            section.set_error(e.what());
        }
    }
}

void configuration_manager::remove_config(const configuration_change_spec &cfg)
{
    for (const auto &id : cfg.base_rules) { global_config_.base_rules.erase(id); }
    for (const auto &id : cfg.user_rules) { global_config_.user_rules.erase(id); }
    for (const auto &id : cfg.rule_filters) { global_config_.rule_filters.erase(id); }
    for (const auto &id : cfg.input_filters) { global_config_.input_filters.erase(id); }
    for (const auto &id : cfg.overrides_by_id) { global_config_.overrides_by_id.erase(id); }
    for (const auto &id : cfg.overrides_by_tags) { global_config_.overrides_by_tags.erase(id); }
    for (const auto &id : cfg.processors) { global_config_.processors.erase(id); }
    for (const auto &id : cfg.scanners) { global_config_.scanners.erase(id); }
    for (const auto &id : cfg.actions) { global_config_.actions.erase(id); }
    for (const auto &[data_id, id] : cfg.rule_data) {
        auto it = global_config_.rule_data.find(data_id);
        if (it != global_config_.rule_data.end()) {
            // Should always be true...
            it->second.values.erase(id);
        }
    }
    for (const auto &[data_id, id] : cfg.exclusion_data) {
        auto it = global_config_.exclusion_data.find(data_id);
        if (it != global_config_.exclusion_data.end()) {
            // Should always be true...
            it->second.values.erase(id);
        }
    }
}

bool configuration_manager::add_or_update(
    const std::string &path, raw_configuration &root, base_ruleset_info &info)
{
    auto it = configs_.find(path);
    if (it != configs_.end()) {
        // Track the change, i.e. removed stuff
        changes_ = changes_ | it->second.content;

        remove_config(it->second);
    } else {
        auto [new_it, res] = configs_.emplace(path, configuration_change_spec{});
        if (!res) {
            return false;
        }
        it = new_it;
    }

    configuration_change_spec new_config;
    configuration_collector collector{new_config, global_config_};

    raw_configuration::map root_map;
    try {
        root_map = static_cast<raw_configuration::map>(root);
    } catch (const bad_cast &e) {
        DDWAF_WARN(
            "Invalid configuration type, expected '{}', obtained '{}'", e.expected(), e.obtained());
        info.set_error(fmt::format("invalid configuration type, expected '{}', obtained '{}'",
            e.expected(), e.obtained()));
        return false;
    }

    load(root_map, collector, info);
    if (new_config.empty()) {
        configs_.erase(it);
        return false;
    }

    changes_ |= new_config.content;
    it->second = std::move(new_config);

    return true;
}

bool configuration_manager::remove(const std::string &path)
{
    auto it = configs_.find(path);
    if (it == configs_.end()) {
        return false;
    }

    changes_ |= it->second.content;

    remove_config(it->second);

    configs_.erase(it);

    return true;
}

std::pair<const configuration_spec &, change_set> configuration_manager::consolidate()
{
    // Copy and reset the current changes
    auto current_change = changes_;
    changes_ = change_set::none;

    return {global_config_, current_change};
}

} // namespace ddwaf
