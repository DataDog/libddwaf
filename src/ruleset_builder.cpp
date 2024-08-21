// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
//
#include <exception>
#include <memory>
#include <set>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "action_mapper.hpp"
#include "exception.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "indexer.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"
#include "parser/specification.hpp"
#include "rule.hpp"
#include "ruleset.hpp"
#include "ruleset_builder.hpp"
#include "ruleset_info.hpp"

namespace ddwaf {

constexpr ruleset_builder::change_state operator|(
    ruleset_builder::change_state lhs, ruleset_builder::change_state rhs)
{
    return static_cast<ruleset_builder::change_state>(
        static_cast<std::underlying_type_t<ruleset_builder::change_state>>(lhs) |
        static_cast<std::underlying_type_t<ruleset_builder::change_state>>(rhs));
}

constexpr ruleset_builder::change_state operator&(
    ruleset_builder::change_state lhs, ruleset_builder::change_state rhs)
{
    return static_cast<ruleset_builder::change_state>(
        static_cast<std::underlying_type_t<ruleset_builder::change_state>>(lhs) &
        static_cast<std::underlying_type_t<ruleset_builder::change_state>>(rhs));
}

namespace {

std::set<rule *> references_to_rules(
    const std::vector<parser::reference_spec> &references, const indexer<rule> &rules)
{
    std::set<rule *> rule_refs;
    if (!references.empty()) {
        for (const auto &ref : references) {
            if (ref.type == parser::reference_type::id) {
                auto *rule = rules.find_by_id(ref.ref_id);
                if (rule == nullptr) {
                    continue;
                }
                rule_refs.emplace(rule);
            } else if (ref.type == parser::reference_type::tags) {
                auto current_refs = rules.find_by_tags(ref.tags);
                rule_refs.merge(current_refs);
            }
        }
    } else {
        // An empty rules reference applies to all rules
        for (const auto &rule : rules) { rule_refs.emplace(rule.get()); }
    }
    return rule_refs;
}

} // namespace

std::shared_ptr<ruleset> ruleset_builder::build(
    parameter::map &root, base_ruleset_info &info, std::optional<object_limits> limits)
{
    if (limits.has_value()) {
        limits_ = limits.value();
    }

    // Load new rules, overrides and exclusions
    auto state = load(root, info);

    if (state == change_state::none) {
        return {};
    }

    constexpr static change_state base_rule_update = change_state::rules | change_state::overrides;
    constexpr static change_state filters_update =
        base_rule_update | change_state::custom_rules | change_state::filters;
    constexpr static change_state processors_update =
        change_state::processors | change_state::scanners;
    // When a configuration with 'rules' or 'rules_override' is received, we
    // need to regenerate the ruleset from the base rules as we want to ensure
    // that there are no side-effects on running contexts.
    if ((state & base_rule_update) != change_state::none) {
        final_base_rules_.clear();

        // Initially, new rules are generated from their spec
        for (const auto &[id, spec] : base_rules_) {
            auto rule_ptr = std::make_shared<ddwaf::rule>(
                id, spec.name, spec.tags, spec.expr, spec.actions, spec.enabled, spec.source);
            final_base_rules_.emplace(rule_ptr);
        }

        // Overrides only impact base rules since user rules can already be modified by the user
        for (const auto &ovrd : overrides_.by_tags) {
            auto rule_targets = references_to_rules(ovrd.targets, final_base_rules_);
            for (const auto &rule_ptr : rule_targets) {
                if (ovrd.enabled.has_value()) {
                    rule_ptr->toggle(*ovrd.enabled);
                }

                if (ovrd.actions.has_value()) {
                    rule_ptr->set_actions(*ovrd.actions);
                }

                for (const auto &[tag, value] : ovrd.tags) {
                    rule_ptr->set_ancillary_tag(tag, value);
                }
            }
        }

        for (const auto &ovrd : overrides_.by_ids) {
            auto rule_targets = references_to_rules(ovrd.targets, final_base_rules_);
            for (const auto &rule_ptr : rule_targets) {
                if (ovrd.enabled.has_value()) {
                    rule_ptr->toggle(*ovrd.enabled);
                }

                if (ovrd.actions.has_value()) {
                    rule_ptr->set_actions(*ovrd.actions);
                }

                for (const auto &[tag, value] : ovrd.tags) {
                    rule_ptr->set_ancillary_tag(tag, value);
                }
            }
        }

        // Remove any disabled rules
        for (auto it = final_base_rules_.begin(); it != final_base_rules_.end();) {
            if (!(*it)->is_enabled()) {
                it = final_base_rules_.erase(it);
            } else {
                ++it;
            }
        }
    }

    if ((state & change_state::custom_rules) != change_state::none) {
        final_user_rules_.clear();

        // Initially, new rules are generated from their spec
        for (const auto &[id, spec] : user_rules_) {
            auto rule_ptr = std::make_shared<ddwaf::rule>(
                id, spec.name, spec.tags, spec.expr, spec.actions, spec.enabled, spec.source);
            if (!rule_ptr->is_enabled()) {
                // Skip disabled rules
                continue;
            }
            final_user_rules_.emplace(rule_ptr);
        }
    }

    // Generate exclusion filters targetting all final rules
    if ((state & filters_update) != change_state::none) {
        rule_filters_.clear();
        input_filters_.clear();

        // First generate rule filters
        for (const auto &[id, filter] : exclusions_.rule_filters) {
            auto rule_targets = references_to_rules(filter.targets, final_base_rules_);
            rule_targets.merge(references_to_rules(filter.targets, final_user_rules_));

            auto filter_ptr = std::make_shared<exclusion::rule_filter>(
                id, filter.expr, std::move(rule_targets), filter.on_match, filter.custom_action);
            rule_filters_.emplace(filter_ptr->get_id(), filter_ptr);
        }

        // Finally input filters
        for (auto &[id, filter] : exclusions_.input_filters) {
            auto rule_targets = references_to_rules(filter.targets, final_base_rules_);
            rule_targets.merge(references_to_rules(filter.targets, final_user_rules_));

            auto filter_ptr = std::make_shared<exclusion::input_filter>(
                id, filter.expr, std::move(rule_targets), filter.filter);
            input_filters_.emplace(filter_ptr->get_id(), filter_ptr);
        }
    }

    // Generate new processors
    if ((state & processors_update) != change_state::none) {
        preprocessors_.clear();
        postprocessors_.clear();

        for (auto &builder : processors_.pre) {
            auto proc = builder.build(scanners_);
            preprocessors_.emplace(proc->get_id(), std::move(proc));
        }

        for (auto &builder : processors_.post) {
            auto proc = builder.build(scanners_);
            postprocessors_.emplace(proc->get_id(), std::move(proc));
        }
    }

    auto rs = std::make_shared<ddwaf::ruleset>();
    rs->insert_rules(final_base_rules_.items());
    rs->insert_rules(final_user_rules_.items());
    rs->insert_filters(rule_filters_);
    rs->insert_filters(input_filters_);
    rs->insert_preprocessors(preprocessors_);
    rs->insert_postprocessors(postprocessors_);
    rs->rule_matchers = rule_matchers_;
    rs->exclusion_matchers = exclusion_matchers_;
    rs->scanners = scanners_.items();
    rs->actions = actions_;
    rs->free_fn = free_fn_;
    rs->event_obfuscator = event_obfuscator_;
    rs->limits = limits_;

    // Since disabled rules aren't added to the final ruleset, we must check
    // again that there are rules available.
    if (rs->rules.empty()) {
        DDWAF_WARN("No valid rules found");
        throw ddwaf::parsing_error("no valid or enabled rules found");
    }

    return rs;
}

ruleset_builder::change_state ruleset_builder::load(parameter::map &root, base_ruleset_info &info)
{
    change_state state = change_state::none;

    auto metadata = parser::at<parameter::map>(root, "metadata", {});
    auto rules_version = parser::at<std::string_view>(metadata, "rules_version", {});
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
            actions_ = parser::v2::parse_actions(actions, section);
            state = state | change_state::actions;
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse actions: {}", e.what());
            section.set_error(e.what());
        }
    }

    if (!actions_) {
        // Ensure that the actions mapper is never invalid
        state = state | change_state::actions;
        actions_ = action_mapper_builder().build_shared();
    }

    it = root.find("rules");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing base rules");
        auto &section = info.add_section("rules");
        try {
            auto rules = static_cast<parameter::vector>(it->second);
            rule_data_ids_.clear();

            if (!rules.empty()) {
                base_rules_ = parser::v2::parse_rules(rules, section, rule_data_ids_, limits_);
            } else {
                DDWAF_DEBUG("Clearing all base rules");
                base_rules_.clear();
            }
            state = state | change_state::rules;
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
            if (!rules.empty()) {
                // Rule data is currently not supported by custom rules so these will
                // be discarded after
                decltype(rule_data_ids_) rule_data_ids;

                auto new_user_rules = parser::v2::parse_rules(
                    rules, section, rule_data_ids, limits_, rule::source_type::user);
                user_rules_ = std::move(new_user_rules);
            } else {
                DDWAF_DEBUG("Clearing all custom rules");
                user_rules_.clear();
            }
            state = state | change_state::custom_rules;
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse custom rules: {}", e.what());
            section.set_error(e.what());
        }
    }

    if (base_rules_.empty() && user_rules_.empty()) {
        // If we haven't received rules and our base ruleset is empty, the
        // WAF can't proceed.
        DDWAF_WARN("No valid rules found");
        throw ddwaf::parsing_error("no valid rules found");
    }

    it = root.find("rules_data");
    if (it != root.end()) {
        DDWAF_DEBUG("Parsing rule data");
        auto &section = info.add_section("rules_data");
        try {
            auto rules_data = static_cast<parameter::vector>(it->second);
            if (!rules_data.empty()) {
                auto new_matchers = parser::v2::parse_data(rules_data, rule_data_ids_, section);
                if (new_matchers.empty()) {
                    // The rules_data array might have unrelated IDs, so we need
                    // to consider "no valid IDs" as an empty rules_data
                    rule_matchers_.clear();
                } else {
                    rule_matchers_ = std::move(new_matchers);
                }
            } else {
                DDWAF_DEBUG("Clearing all rule data");
                rule_matchers_.clear();
            }
            state = state | change_state::rule_data;
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
            if (!overrides.empty()) {
                overrides_ = parser::v2::parse_overrides(overrides, section);
            } else {
                DDWAF_DEBUG("Clearing all overrides");
                overrides_.clear();
            }
            state = state | change_state::overrides;
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
            filter_data_ids_.clear();
            if (!exclusions.empty()) {
                exclusions_ =
                    parser::v2::parse_filters(exclusions, section, filter_data_ids_, limits_);
            } else {
                DDWAF_DEBUG("Clearing all exclusions");
                exclusions_.clear();
            }
            state = state | change_state::filters;
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
            if (!exclusions_data.empty()) {
                auto new_matchers =
                    parser::v2::parse_data(exclusions_data, filter_data_ids_, section);
                if (new_matchers.empty()) {
                    // The exclusions_data array might have unrelated IDs, so we need
                    // to consider "no valid IDs" as an empty exclusions_data
                    exclusion_matchers_.clear();
                } else {
                    exclusion_matchers_ = std::move(new_matchers);
                }
            } else {
                DDWAF_DEBUG("Clearing all exclusion data");
                exclusion_matchers_.clear();
            }
            state = state | change_state::exclusion_data;
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
            if (!processors.empty()) {
                processors_ = parser::v2::parse_processors(processors, section, limits_);
            } else {
                DDWAF_DEBUG("Clearing all processors");
                processors_.clear();
            }
            state = state | change_state::processors;
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
            if (!scanners.empty()) {
                scanners_ = parser::v2::parse_scanners(scanners, section);
            } else {
                DDWAF_DEBUG("Clearing all scanners");
                scanners_.clear();
            }
            state = state | change_state::scanners;
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse scanners: {}", e.what());
            section.set_error(e.what());
        }
    }

    return state;
}

} // namespace ddwaf
