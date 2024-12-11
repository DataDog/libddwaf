// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2024 Datadog, Inc.

#include <exception>
#include <string>
#include <string_view>
#include <utility>

#include "configuration/actions_parser.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/data_parser.hpp"
#include "configuration/exclusion_parser.hpp"
#include "configuration/manager.hpp"
#include "configuration/processor_parser.hpp"
#include "configuration/rule_override_parser.hpp"
#include "configuration/rule_parser.hpp"
#include "configuration/scanner_parser.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "ruleset_info.hpp"

namespace ddwaf {

using content_set = configuration_spec::content_set;

configuration_spec configuration_manager::load(parameter::map &root, base_ruleset_info &info)
{
    configuration_spec config;

    auto metadata = at<parameter::map>(root, "metadata", {});
    auto rules_version = at<std::string_view>(metadata, "rules_version", {});
    if (!rules_version.empty()) {
        info.set_ruleset_version(rules_version);
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
                config.content = config.content | content_set::actions;
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
                config.content = config.content | content_set::rules;
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
                config.content = config.content | content_set::custom_rules;
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
                config.content = config.content | content_set::rule_data;
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
                config.content = config.content | content_set::overrides;
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
                config.content = config.content | content_set::filters;
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
                config.content = config.content | content_set::exclusion_data;
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
                config.content = config.content | content_set::processors;
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
                config.content = config.content | content_set::scanners;
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

bool configuration_manager::set_default(parameter::map &root, base_ruleset_info &info)
{
    auto new_config = load(root, info);

    if (new_config.empty()) {
        return false;
    }

    default_config_ = std::move(new_config);

    return true;
}

bool configuration_manager::add(
    const std::string &path, parameter::map &root, base_ruleset_info &info)
{
    auto new_config = load(root, info);
    if (new_config.empty()) {
        return false;
    }

    configs_[path] = std::move(new_config);

    return true;
}

bool configuration_manager::update(
    const std::string &path, parameter::map &root, base_ruleset_info &info)
{
    auto it = configs_.find(path);
    if (it == configs_.end()) {
        return false;
    }

    remove_config_ids(it);

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

    remove_config_ids(it);

    configs_.erase(it);

    return true;
}

configuration_spec configuration_manager::consolidate() const { return {}; }

} // namespace ddwaf
