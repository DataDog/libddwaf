// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <builder.hpp>
#include <charconv>
#include <exception.hpp>
#include <log.hpp>
#include <parser/common.hpp>
#include <parser/parser.hpp>
#include <string_view>

namespace ddwaf {

builder::change_state operator|(builder::change_state lhs, builder::change_state rhs)
{
    return static_cast<builder::change_state>(
        static_cast<std::underlying_type<builder::change_state>::type>(lhs) |
        static_cast<std::underlying_type<builder::change_state>::type>(rhs));
}

builder::change_state operator&(builder::change_state lhs, builder::change_state rhs)
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

std::shared_ptr<ruleset> builder::build_helper(
    parameter::map root, ruleset_info &info, object_limits limits)
{
    manifest_builder mb;
    rule_data::dispatcher dispatcher;

    // First stage: load new rules, overrides and exclusions

    // TODO generating rule_spec is extra overhead, we can just generate the pointers
    auto state = load(root, info, limits);

    // Second stage: regenerate intermediate structures
    if ((state & change_state::rules) != change_state::none) {
        // If the rules have changed, regenerate the rule_specs_by_tag_ mkmap
        for (auto &[id, rule] : base_rules_) { rule_specs_by_tag_.insert(rule.tags, id); }
    }

    // If rules have changed or overrides have changed...
    if ((state & (change_state::rules | change_state::overrides)) != change_state::none) {
        // Third stage: Apply overrides

        // Invalidate any existing overrides
        overridden_rules_.clear();

        // First apply overrides by ID
        for (const auto &ovrd : overrides_.by_ids) {
            for (const auto &target : ovrd.targets) {
                auto rule_it = base_rules_.find(target.rule_id);

                // Sanity check
                if (rule_it == base_rules_.end() ||
                    overridden_rules_.find(target.rule_id) != overridden_rules_.end()) {
                    continue;
                }

                auto [new_rule_it, res] =
                    overridden_rules_.emplace(target.rule_id, rule_it->second);

                auto &new_rule = new_rule_it->second;
                if (ovrd.enabled.has_value()) {
                    new_rule.enabled = *ovrd.enabled;
                }

                if (ovrd.actions.has_value()) {
                    new_rule.actions = *ovrd.actions;
                }
            }
        }

        for (const auto &ovrd : overrides_.by_tags) {
            std::set<std::string> rules_targets;

            // This is far from ideal...
            for (const auto &target : ovrd.targets) {
                std::vector<std::pair<std::string_view, std::string_view>> tags;
                tags.reserve(target.tags.size());
                for (const auto &[k, v] : target.tags) { tags.emplace_back(k, v); }
                auto current_targets = rule_specs_by_tag_.multifind(tags);
                rules_targets.merge(current_targets);
            }

            for (const auto &id : rules_targets) {
                if (overridden_rules_.find(id) != overridden_rules_.end()) {
                    // We can't override twice!
                    continue;
                }

                // If the ID is in the container, it means the rule exists,
                // but we can check anyway
                auto rule_it = base_rules_.find(id);
                if (rule_it == base_rules_.end()) {
                    continue;
                }

                auto [new_rule_it, res] = overridden_rules_.emplace(id, rule_it->second);

                auto &new_rule = new_rule_it->second;
                if (ovrd.enabled.has_value()) {
                    new_rule.enabled = *ovrd.enabled;
                }

                if (ovrd.actions.has_value()) {
                    new_rule.actions = *ovrd.actions;
                }
            }
        }

        // Fourth stage: regenerate rules, we should only need to do this if
        final_rules_.clear();
        final_rules_.reserve(base_rules_.size());

        for (const auto &[id, spec] : base_rules_) {
            auto override_it = overridden_rules_.find(id);
            if (override_it != overridden_rules_.end()) {
                final_rules_.emplace(id, std::make_shared<ddwaf::rule>(id, override_it->second));
            } else {
                final_rules_.emplace(id, std::make_shared<ddwaf::rule>(id, spec));
            }
        }
    }

    // Fifth stage: generate intermediate structures
    /*    for (const auto &[id, rule] : final_rules_) {*/
    /*rules_by_tags_.insert(rule->tags, rule);*/
    /*}*/

    // Sixth stage: generate exclusion filters

    ddwaf::ruleset rs;
    for (auto &[id, rule] : final_rules_) { rs.insert_rule(rule); }

    return std::make_shared<ddwaf::ruleset>(std::move(rs));
}

builder::change_state builder::load(parameter::map &root, ruleset_info &info, object_limits limits)
{
    manifest_builder mb;
    rule_data::dispatcher dispatcher;

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
