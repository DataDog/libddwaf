// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/specification.hpp"
#include <builder.hpp>
#include <charconv>
#include <exception.hpp>
#include <log.hpp>
#include <parser/common.hpp>
#include <parser/parser.hpp>
#include <string_view>

namespace ddwaf {

constexpr builder::change_state operator|(builder::change_state lhs, builder::change_state rhs)
{
    return static_cast<builder::change_state>(
        static_cast<std::underlying_type<builder::change_state>::type>(lhs) |
        static_cast<std::underlying_type<builder::change_state>::type>(rhs));
}

constexpr builder::change_state operator&(builder::change_state lhs, builder::change_state rhs)
{
    return static_cast<builder::change_state>(
        static_cast<std::underlying_type<builder::change_state>::type>(lhs) &
        static_cast<std::underlying_type<builder::change_state>::type>(rhs));
}

std::shared_ptr<ruleset> builder::build(parameter object, ruleset_info &info, object_limits limits)
{
    parameter::map ruleset = object;

    ddwaf::ruleset rs;

    auto version = parser::parse_schema_version(ruleset);
    switch (version) {
    case 1:
        parser::v1::parse(ruleset, info, rs, limits);
        break;
    case 2:
        parser::v2::parse(ruleset, info, rs, limits);
        break;
    case 3: // Experimental
        return build_helper(ruleset, info, limits);
    default:
        DDWAF_ERROR("incompatible ruleset version %u.x", version);
        throw unsupported_version();
    }

    return std::make_shared<ddwaf::ruleset>(std::move(rs));
}

namespace {

std::set<rule::ptr> target_to_rules(const std::vector<parser::rule_target_spec> &targets,
    const std::unordered_map<std::string_view, rule::ptr> &rules,
    const rule_tag_map &rules_by_tags)
{
    std::set<rule::ptr> rule_targets;
    if (!targets.empty()) {
        for (const auto &target : targets) {
            if (target.type == parser::target_type::id) {
                auto rule_it = rules.find(target.rule_id);
                if (rule_it == rules.end()) {
                    continue;
                }
                rule_targets.emplace(rule_it->second);
            } else if (target.type == parser::target_type::tags) {
                auto current_targets = rules_by_tags.multifind(target.tags);
                rule_targets.merge(current_targets);
            }
        }
    } else {
        // An empty rules target applies to all rules
        for (const auto &[id, rule] : rules) {
            rule_targets.emplace(rule);
        }
    }
    return rule_targets;
}

} // namespace

std::shared_ptr<ruleset> builder::build_helper(
    parameter::map root, ruleset_info &info, object_limits limits)
{
    manifest_builder mb;
    rule_data::dispatcher dispatcher;

    // Load new rules, overrides and exclusions
    auto state = load(root, info, mb, dispatcher, limits);

    constexpr change_state rule_update = change_state::rules | change_state::overrides;
    constexpr change_state filters_update = rule_update | change_state::filters;

    if ((state & rule_update) != change_state::none) {
        // A new ruleset or a new set of overrides requires a new ruleset
        for (const auto &[id, spec] : base_rules_) {
            auto rule_ptr = std::make_shared<ddwaf::rule>(id, spec);
            final_rules_.emplace(id, rule_ptr);
            rules_by_tags_.insert(rule_ptr->tags, rule_ptr);
        }

        // Apply overrides by ID
        std::unordered_set<rule*> overridden_rules;
        for (const auto &ovrd : overrides_.by_ids) {
            auto rule_targets = target_to_rules(ovrd.targets, final_rules_, rules_by_tags_);
            for (const auto &rule_ptr : rule_targets) {
                if (overridden_rules.find(rule_ptr.get()) != overridden_rules.end()) { continue; }

                if (ovrd.enabled.has_value()) {
                    rule_ptr->toggle(*ovrd.enabled);
                }

                if (ovrd.actions.has_value()) {
                    rule_ptr->actions = *ovrd.actions;
                }

                overridden_rules.emplace(rule_ptr.get());
            }
        }

        // Apply overrides by tag
        for (const auto &ovrd : overrides_.by_tags) {
            auto rule_targets = target_to_rules(ovrd.targets, final_rules_, rules_by_tags_);
            for (const auto &rule_ptr : rule_targets) {
                if (overridden_rules.find(rule_ptr.get()) != overridden_rules.end()) { continue; }

                if (ovrd.enabled.has_value()) {
                    rule_ptr->toggle(*ovrd.enabled);
                }

                if (ovrd.actions.has_value()) {
                    rule_ptr->actions = *ovrd.actions;
                }
            }
        }
    }

    // Generate exclusion filters
    if ((state & filters_update) != change_state::none) {
        // First apply unconditional_rule_filters
        for (const auto &[id, filter] : exclusions_.unconditional_rule_filters) {
           auto rule_targets = target_to_rules(filter.targets, final_rules_, rules_by_tags_);
            for (const auto &rule_ptr : rule_targets) {
                rule_ptr->toggle(false);
            }
        }

        // Then rule filters
        for (const auto &[id, filter] : exclusions_.rule_filters) {
            auto rule_targets = target_to_rules(filter.targets, final_rules_, rules_by_tags_);
            auto filter_ptr = std::make_shared<exclusion::rule_filter>(
                id, filter.conditions, std::move(rule_targets));
            rule_filters_.emplace(filter_ptr->get_id(), filter_ptr);
        }

        // Finally input filters
        for (auto &[id, filter] : exclusions_.input_filters) {
            auto rule_targets = target_to_rules(filter.targets, final_rules_, rules_by_tags_);

           // TODO Fix uncopyable path_trie
            auto filter_ptr = std::make_shared<exclusion::input_filter>(
                id, filter.conditions, std::move(rule_targets), std::move(filter.filter));
            input_filters_.emplace(filter_ptr->get_id(), filter_ptr);
        }
    }

    ddwaf::ruleset rs;
    for (auto &[id, rule] : final_rules_) { rs.insert_rule(rule); }
    rs.dispatcher = std::move(dispatcher);
    rs.manifest = mb.build_manifest();
    rs.rule_filters = std::move(rule_filters_);
    rs.input_filters = std::move(input_filters_);

    return std::make_shared<ddwaf::ruleset>(std::move(rs));
}

builder::change_state builder::load(parameter::map &root, ruleset_info &info,
        manifest_builder &mb, rule_data::dispatcher &dispatcher, object_limits limits)
{
    parser::v3::parser p(info, mb, dispatcher, limits);

    change_state state = change_state::none;

    auto it = root.find("rules");
    if (it != root.end()) {
        parameter::vector rules = it->second;
        auto new_base_rules = p.parse_rules(rules);

        if (new_base_rules.empty()) {
            throw ddwaf::parsing_error("no valid rules found");
        }

        // Upon reaching this stage, we know our base ruleset is valid
        base_rules_ = std::move(new_base_rules);
        state = state | change_state::rules;
    } else {
        if (base_rules_.empty()) {
            // A ruleset has been provided as part of ddwaf_init without any rules
            throw std::runtime_error("no rules available");
        }
    }

    it = root.find("rules_override");
    if (it != root.end()) {
        parameter::vector overrides = it->second;
        auto new_overrides = p.parse_overrides(overrides);

        if (new_overrides.empty()) {
            // We can continue whilst ignoring the lack of overrides
            DDWAF_WARN("No valid overrides provided");
        } else {
            overrides_ = std::move(new_overrides);
            state = state | change_state::overrides;
        }
    }

    it = root.find("exclusions");
    if (it != root.end()) {
        parameter::vector exclusions = it->second;
        auto new_exclusions = p.parse_filters(exclusions);

        if (new_exclusions.empty()) {
            // Ignore a non-critical error
            DDWAF_WARN("No valid exclusion filters provided");
        } else {
            exclusions_ = std::move(new_exclusions);
            state = state | change_state::filters;
        }
    }

    return state;
}

} // namespace ddwaf
