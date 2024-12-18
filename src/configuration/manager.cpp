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
#include "configuration/data_parser.hpp"
#include "configuration/exclusion_parser.hpp"
#include "configuration/legacy_rule_parser.hpp"
#include "configuration/manager.hpp"
#include "configuration/processor_parser.hpp"
#include "configuration/rule_override_parser.hpp"
#include "configuration/rule_parser.hpp"
#include "configuration/scanner_parser.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "ruleset_info.hpp"

namespace ddwaf {

configuration_spec configuration_manager::load(parameter::map &root, base_ruleset_info &info)
{
    configuration_spec config;

    auto metadata = at<parameter::map>(root, "metadata", {});
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
                auto rules = static_cast<parameter::vector>(it->second);
                if (!rules.empty() && parse_legacy_rules(rules, config, ids_, section, limits_)) {
                    config.content = config.content | change_set::rules;
                }
            } catch (const std::exception &e) {
                DDWAF_WARN("Failed to parse rules: {}", e.what());
                section.set_error(e.what());
            }
        }

        return config;
    }

    auto it = root.find("actions");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing actions");
        auto &section = info.add_section("actions");
        try {
            // If the actions array is empty, an empty action mapper will be
            // generated. Note that this mapper will still contain the default
            // actions.
            auto actions = static_cast<parameter::vector>(it->second);
            if (!actions.empty() && parse_actions(actions, config, ids_, section)) {
                config.content = config.content | change_set::actions;
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
            auto rules = static_cast<parameter::vector>(it->second);
            if (!rules.empty() && parse_base_rules(rules, config, ids_, section, limits_)) {
                config.content = config.content | change_set::rules;
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
            auto rules = static_cast<parameter::vector>(it->second);
            if (!rules.empty() && parse_user_rules(rules, config, ids_, section, limits_)) {
                config.content = config.content | change_set::custom_rules;
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
            auto rules_data = static_cast<parameter::vector>(it->second);
            if (!rules_data.empty() && parse_rule_data(rules_data, config, section)) {
                config.content = config.content | change_set::rule_data;
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
            auto overrides = static_cast<parameter::vector>(it->second);
            if (!overrides.empty() && parse_overrides(overrides, config, section)) {
                config.content = config.content | change_set::overrides;
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
            auto exclusions = static_cast<parameter::vector>(it->second);
            if (!exclusions.empty() && parse_filters(exclusions, config, ids_, section, limits_)) {
                config.content = config.content | change_set::filters;
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse exclusions: {}", e.what());
            section.set_error(e.what());
        }
    }

    it = root.find("exclusion_data");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing exclusion data");
        auto &section = info.add_section("exclusions_data");
        try {
            auto exclusions_data = static_cast<parameter::vector>(it->second);
            if (!exclusions_data.empty() &&
                parse_exclusion_data(exclusions_data, config, section)) {
                config.content = config.content | change_set::exclusion_data;
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
            auto processors = static_cast<parameter::vector>(it->second);
            if (!processors.empty() &&
                parse_processors(processors, config, ids_, section, limits_)) {
                config.content = config.content | change_set::processors;
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
            auto scanners = static_cast<parameter::vector>(it->second);
            if (!scanners.empty() && parse_scanners(scanners, config, ids_, section)) {
                config.content = config.content | change_set::scanners;
            }
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse scanners: {}", e.what());
            section.set_error(e.what());
        }
    }

    return config;
}

void configuration_manager::remove_config_ids(
    const std::unordered_map<std::string, configuration_spec>::const_iterator &it)
{
    // Remove all IDs provided by this configuration
    for (const auto &rule : it->second.base_rules) { ids_.rules.erase(rule.id); }
    for (const auto &rule : it->second.user_rules) { ids_.rules.erase(rule.id); }
    for (const auto &filter : it->second.rule_filters) { ids_.filters.erase(filter.id); }
    for (const auto &filter : it->second.input_filters) { ids_.filters.erase(filter.id); }
    for (const auto &proc : it->second.processors) { ids_.processors.erase(proc.id); }
    for (const auto &scnr : it->second.scanners) { ids_.scanners.erase(scnr->get_id_ref()); }
    for (const auto &action : it->second.actions) { ids_.actions.erase(action.id); }
}

bool configuration_manager::add_or_update(
    const std::string &path, parameter::map &root, base_ruleset_info &info)
{
    auto it = configs_.find(path);
    if (it != configs_.end()) {
        // Track the change, i.e. removed stuff
        changes_ = changes_ | it->second.content;

        remove_config_ids(it);
    } else {
        auto [new_it, res] = configs_.emplace(path, configuration_spec{});
        if (!res) {
            return false;
        }
        it = new_it;
    }

    auto new_config = load(root, info);
    if (new_config.empty()) {
        configs_.erase(it);
        return false;
    }

    it->second = std::move(new_config);

    return true;
}

bool configuration_manager::remove(const std::string &path)
{
    auto it = configs_.find(path);
    if (it == configs_.end()) {
        return false;
    }

    changes_ = changes_ | it->second.content;

    remove_config_ids(it);

    configs_.erase(it);

    return true;
}

merged_configuration_spec configuration_manager::merge()
{
    merged_configuration_spec merged;

    auto emplace_contents = []<typename T>(std::vector<T> &destination, std::vector<T> &source) {
        destination.reserve(destination.size() + source.size());
        for (const auto &item : source) { destination.emplace_back(item); }
    };

    for (auto [path, cfg] : configs_) {
        merged.content = merged.content | cfg.content;

        emplace_contents(merged.base_rules, cfg.base_rules);
        emplace_contents(merged.user_rules, cfg.user_rules);
        emplace_contents(merged.overrides_by_id, cfg.overrides_by_id);
        emplace_contents(merged.overrides_by_tags, cfg.overrides_by_tags);
        emplace_contents(merged.rule_filters, cfg.rule_filters);
        emplace_contents(merged.input_filters, cfg.input_filters);
        emplace_contents(merged.processors, cfg.processors);
        emplace_contents(merged.actions, cfg.actions);

        for (const auto &data : cfg.rule_data) {
            auto it = merged.rule_data.find(data.id);
            if (it == merged.rule_data.end()) {
                merged.rule_data.emplace(data.id, data);
            } else {
                auto &dest_vec = it->second.values;
                dest_vec.insert(dest_vec.begin(), data.values.begin(), data.values.end());
            }
        }

        for (const auto &data : cfg.exclusion_data) {
            auto it = merged.exclusion_data.find(data.id);
            if (it == merged.exclusion_data.end()) {
                merged.exclusion_data.emplace(data.id, data);
            } else {
                auto &dest_vec = it->second.values;
                dest_vec.insert(dest_vec.begin(), data.values.begin(), data.values.end());
            }
        }

        for (const auto &scnr : cfg.scanners) { merged.scanners.emplace(scnr); }
    }

    return merged;
}

merged_configuration_spec configuration_manager::consolidate()
{
    merged_configuration_spec merged = merge();
    merged.content = merged.content | changes_;
    changes_ = change_set::none;
    return merged;
}

} // namespace ddwaf
