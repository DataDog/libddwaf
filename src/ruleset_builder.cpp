// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/specification.hpp"
#include <charconv>
#include <exception.hpp>
#include <log.hpp>
#include <parser/common.hpp>
#include <parser/parser.hpp>
#include <ruleset_builder.hpp>
#include <string_view>

namespace ddwaf {

constexpr ruleset_builder::change_state operator|(
    ruleset_builder::change_state lhs, ruleset_builder::change_state rhs)
{
    return static_cast<ruleset_builder::change_state>(
        static_cast<std::underlying_type<ruleset_builder::change_state>::type>(lhs) |
        static_cast<std::underlying_type<ruleset_builder::change_state>::type>(rhs));
}

constexpr ruleset_builder::change_state operator&(
    ruleset_builder::change_state lhs, ruleset_builder::change_state rhs)
{
    return static_cast<ruleset_builder::change_state>(
        static_cast<std::underlying_type<ruleset_builder::change_state>::type>(lhs) &
        static_cast<std::underlying_type<ruleset_builder::change_state>::type>(rhs));
}

namespace {

std::set<rule *> target_to_rules(const std::vector<parser::rule_target_spec> &targets,
    const std::unordered_map<std::string_view, rule::ptr> &rules, const rule_tag_map &rules_by_tags)
{
    if (rules_by_tags.empty()) {
        return {};
    }

    std::set<rule *> rule_targets;
    if (!targets.empty()) {
        for (const auto &target : targets) {
            if (target.type == parser::target_type::id) {
                auto rule_it = rules.find(target.rule_id);
                if (rule_it == rules.end()) {
                    continue;
                }
                rule_targets.emplace(rule_it->second.get());
            } else if (target.type == parser::target_type::tags) {
                auto current_targets = rules_by_tags.multifind(target.tags);
                rule_targets.merge(current_targets);
            }
        }
    } else {
        // An empty rules target applies to all rules
        for (const auto &[id, rule] : rules) { rule_targets.emplace(rule.get()); }
    }
    return rule_targets;
}

} // namespace

std::shared_ptr<ruleset> ruleset_builder::build(parameter::map &root, ruleset_info &info)
{
    // Load new rules, overrides and exclusions
    auto state = load(root, info);

    if (state == change_state::none) {
        return {};
    }

    constexpr static change_state base_rule_update = change_state::rules | change_state::overrides;
    constexpr static change_state filters_update =
        base_rule_update | change_state::custom_rules | change_state::filters;
    constexpr static change_state manifest_update =
        change_state::rules | change_state::custom_rules | change_state::filters;

    // When a configuration with 'rules', 'rules_data' or 'rules_override' is
    // received, we need to regenerate the ruleset from the base rules as we
    // want to ensure that there are no side-effects on running contexts.
    if ((state & base_rule_update) != change_state::none) {
        final_base_rules_.clear();
        base_rules_by_tags_.clear();
        inputs_from_base_rules_.clear();

        // Initially, new rules are generated from their spec
        for (const auto &[id, spec] : base_rules_) {
            for (const auto &cond : spec.conditions) {
                for (const auto &target : cond->get_targets()) {
                    inputs_from_base_rules_.emplace(target.root);
                }
            }

            auto rule_ptr = std::make_shared<ddwaf::rule>(
                id, spec.name, spec.tags, spec.conditions, spec.actions, spec.enabled, spec.source);

            // The string_view should be owned by the rule_ptr
            final_base_rules_.emplace(rule_ptr->id, rule_ptr);
            base_rules_by_tags_.insert(rule_ptr->tags, rule_ptr.get());
        }

        for (const auto &ovrd : overrides_.by_tags) {
            auto rule_targets =
                target_to_rules(ovrd.targets, final_base_rules_, base_rules_by_tags_);
            for (const auto &rule_ptr : rule_targets) {
                if (ovrd.enabled.has_value()) {
                    rule_ptr->toggle(*ovrd.enabled);
                }

                if (ovrd.actions.has_value()) {
                    rule_ptr->actions = *ovrd.actions;
                }
            }
        }

        for (const auto &ovrd : overrides_.by_ids) {
            auto rule_targets =
                target_to_rules(ovrd.targets, final_base_rules_, base_rules_by_tags_);
            for (const auto &rule_ptr : rule_targets) {
                if (ovrd.enabled.has_value()) {
                    rule_ptr->toggle(*ovrd.enabled);
                }

                if (ovrd.actions.has_value()) {
                    rule_ptr->actions = *ovrd.actions;
                }
            }
        }
    }

    if ((state & change_state::custom_rules) != change_state::none) {
        final_user_rules_.clear();
        user_rules_by_tags_.clear();
        inputs_from_user_rules_.clear();

        // Initially, new rules are generated from their spec
        for (const auto &[id, spec] : user_rules_) {
            for (const auto &cond : spec.conditions) {
                for (const auto &target : cond->get_targets()) {
                    inputs_from_user_rules_.emplace(target.root);
                }
            }

            auto rule_ptr = std::make_shared<ddwaf::rule>(
                id, spec.name, spec.tags, spec.conditions, spec.actions, spec.enabled, spec.source);

            // The string_view should be owned by the rule_ptr
            final_user_rules_.emplace(rule_ptr->id, rule_ptr);
            user_rules_by_tags_.insert(rule_ptr->tags, rule_ptr.get());
        }
    }

    // Generate exclusion filters targetting all final rules
    if ((state & filters_update) != change_state::none) {
        rule_filters_.clear();
        input_filters_.clear();
        inputs_from_filters_.clear();

        // First generate rule filters
        for (const auto &[id, filter] : exclusions_.rule_filters) {
            auto rule_targets =
                target_to_rules(filter.targets, final_base_rules_, base_rules_by_tags_);
            rule_targets.merge(
                target_to_rules(filter.targets, final_user_rules_, user_rules_by_tags_));

            auto filter_ptr = std::make_shared<exclusion::rule_filter>(
                id, filter.conditions, std::move(rule_targets));
            rule_filters_.emplace(filter_ptr->get_id(), filter_ptr);

            for (const auto &cond : filter.conditions) {
                for (const auto &target : cond->get_targets()) {
                    inputs_from_filters_.emplace(target.root);
                }
            }
        }

        // Finally input filters
        for (auto &[id, filter] : exclusions_.input_filters) {
            auto rule_targets =
                target_to_rules(filter.targets, final_base_rules_, base_rules_by_tags_);
            rule_targets.merge(
                target_to_rules(filter.targets, final_user_rules_, user_rules_by_tags_));

            auto filter_ptr = std::make_shared<exclusion::input_filter>(
                id, filter.conditions, std::move(rule_targets), filter.filter);
            input_filters_.emplace(filter_ptr->get_id(), filter_ptr);

            for (const auto &target : filter.filter->get_targets()) {
                inputs_from_filters_.emplace(target);
            }

            for (const auto &cond : filter.conditions) {
                for (const auto &target : cond->get_targets()) {
                    inputs_from_filters_.emplace(target.root);
                }
            }
        }
    }

    if ((state & manifest_update) != change_state::none) {
        // Remove unnecessary targets using all the targets contained within
        // rule conditions, filter conditions and object filters
        std::unordered_set<manifest::target_type> all_targets;
        all_targets.insert(inputs_from_base_rules_.begin(), inputs_from_base_rules_.end());
        all_targets.insert(inputs_from_user_rules_.begin(), inputs_from_user_rules_.end());
        all_targets.insert(inputs_from_filters_.begin(), inputs_from_filters_.end());

        target_manifest_.remove_unused(all_targets);
    }

    auto rs = std::make_shared<ddwaf::ruleset>();
    rs->manifest = target_manifest_;
    rs->insert_rules(final_base_rules_);
    rs->insert_rules(final_user_rules_);
    rs->dynamic_processors = dynamic_processors_;
    rs->rule_filters = rule_filters_;
    rs->input_filters = input_filters_;
    rs->free_fn = free_fn_;
    rs->event_obfuscator = event_obfuscator_;

    return rs;
}

ruleset_builder::change_state ruleset_builder::load(parameter::map &root, ruleset_info &info)
{
    change_state state = change_state::none;

    auto metadata = parser::at<parameter::map>(root, "metadata", {});
    auto rules_version = metadata.find("rules_version");
    if (rules_version != metadata.end()) {
        info.set_version(static_cast<std::string_view>(rules_version->second));
    }

    auto it = root.find("rules");
    if (it != root.end()) {
        decltype(rule_data_ids_) rule_data_ids;

        auto rules = static_cast<parameter::vector>(it->second);
        auto new_base_rules =
            parser::v2::parse_rules(rules, info, target_manifest_, rule_data_ids, limits_);

        if (!new_base_rules.empty()) {
            // Upon reaching this stage, we know our base ruleset is valid
            base_rules_ = std::move(new_base_rules);
            rule_data_ids_ = std::move(rule_data_ids);
            state = state | change_state::rules;
        }
    }

    it = root.find("custom_rules");
    if (it != root.end()) {
        decltype(rule_data_ids_) rule_data_ids;

        auto rules = static_cast<parameter::vector>(it->second);
        if (!rules.empty()) {
            auto new_user_rules = parser::v2::parse_rules(
                rules, info, target_manifest_, rule_data_ids, limits_, rule::source_type::user);

            if (new_user_rules.empty()) {
                DDWAF_WARN("No valid custom rules found");
            } else {
                // Upon reaching this stage, we know our base ruleset is valid
                user_rules_ = std::move(new_user_rules);
                state = state | change_state::custom_rules;
            }
        } else {
            user_rules_.clear();
            state = state | change_state::custom_rules;
        }
    }

    if (base_rules_.empty() && user_rules_.empty()) {
        // If we haven't received rules and our base ruleset is empty, the
        // WAF can't proceed.
        throw ddwaf::parsing_error("no valid rules found");
    }

    it = root.find("rules_data");
    if (it != root.end()) {
        auto rules_data = static_cast<parameter::vector>(it->second);
        if (!rules_data.empty()) {
            auto new_processors = parser::v2::parse_rule_data(rules_data, rule_data_ids_);
            if (new_processors.empty()) {
                // The rules_data array might have unrelated IDs, so we need
                // to consider "no valid IDs" as an empty rules_data
                dynamic_processors_.clear();
                state = state | change_state::data;
            } else {
                dynamic_processors_ = std::move(new_processors);
                state = state | change_state::data;
            }
        } else {
            dynamic_processors_.clear();
            state = state | change_state::data;
        }
    }

    it = root.find("rules_override");
    if (it != root.end()) {
        auto overrides = static_cast<parameter::vector>(it->second);
        if (!overrides.empty()) {
            auto new_overrides = parser::v2::parse_overrides(overrides);
            if (new_overrides.empty()) {
                // We can continue whilst ignoring the lack of overrides
                DDWAF_WARN("No valid overrides provided");
            } else {
                overrides_ = std::move(new_overrides);
                state = state | change_state::overrides;
            }
        } else {
            overrides_.clear();
            state = state | change_state::overrides;
        }
    }

    it = root.find("exclusions");
    if (it != root.end()) {
        auto exclusions = static_cast<parameter::vector>(it->second);
        if (!exclusions.empty()) {
            auto new_exclusions = parser::v2::parse_filters(exclusions, target_manifest_, limits_);

            if (new_exclusions.empty()) {
                // We can continue whilst ignoring the lack of exclusions
                DDWAF_WARN("No valid exclusion filters provided");
            } else {
                exclusions_ = std::move(new_exclusions);
                state = state | change_state::filters;
            }
        } else {
            exclusions_.clear();
            state = state | change_state::filters;
        }
    }

    return state;
}

} // namespace ddwaf
