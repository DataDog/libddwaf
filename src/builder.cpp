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

std::shared_ptr<ruleset> builder::build(parameter object, ruleset_info &info)
{
    parameter::map ruleset = object;

    unsigned version = parser::parse_schema_version(ruleset);
    if (version == 1) {
        ddwaf::ruleset rs;
        parser::v1::parse(ruleset, info, rs, limits_);
        return std::make_shared<ddwaf::ruleset>(std::move(rs));
    }

    if (version != 2) {
        DDWAF_ERROR("incompatible ruleset version %u.x", version);
        throw unsupported_version();
    }

    return build_helper(ruleset, info);
}

namespace {

std::set<rule::ptr> target_to_rules(const std::vector<parser::rule_target_spec> &targets,
    const std::unordered_map<std::string_view, rule::ptr> &rules, const rule_tag_map &rules_by_tags)
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
        for (const auto &[id, rule] : rules) { rule_targets.emplace(rule); }
    }
    return rule_targets;
}

} // namespace

std::shared_ptr<ruleset> builder::build_helper(parameter::map &root, ruleset_info &info)
{
    // Load new rules, overrides and exclusions
    auto state = load(root, info);

    if (state == change_state::none) {
        return {};
    }

    constexpr change_state rule_update =
        change_state::rules | change_state::data | change_state::overrides;
    constexpr change_state filters_update = rule_update | change_state::filters;
    constexpr change_state manifest_update = change_state::rules | change_state::filters;

    if ((state & rule_update) != change_state::none) {
        final_rules_.clear();
        rules_by_tags_.clear();
        targets_from_rules_.clear();

        // A new ruleset, new rule data or a new set of overrides requires a new ruleset
        for (const auto &[id, spec] : base_rules_) {
            std::vector<condition::ptr> conditions;
            conditions.reserve(spec.conditions.size());

            for (const auto &cond_spec : spec.conditions) {
                std::shared_ptr<rule_processor::base> processor;
                if (!cond_spec.data_id.empty() && !cond_spec.processor) {
                    auto it = dynamic_processors_.find(cond_spec.data_id);
                    if (it != dynamic_processors_.end()) {
                        processor = it->second;
                    }
                } else {
                    processor = cond_spec.processor;
                }

                for (const auto &target : cond_spec.targets) {
                    targets_from_rules_.emplace(target.root);
                }

                conditions.emplace_back(std::make_shared<condition>(cond_spec.targets,
                    cond_spec.transformers, std::move(processor), limits_, cond_spec.source));
            }

            auto rule_ptr = std::make_shared<ddwaf::rule>(
                id, spec.name, spec.tags, std::move(conditions), spec.actions, spec.enabled);

            // Don't insert id as it's own by the builder
            final_rules_.emplace(rule_ptr->id, rule_ptr);
            rules_by_tags_.insert(rule_ptr->tags, rule_ptr);
        }

        // Apply overrides by ID
        std::unordered_set<rule *> overridden_rules;
        for (const auto &ovrd : overrides_.by_ids) {
            auto rule_targets = target_to_rules(ovrd.targets, final_rules_, rules_by_tags_);
            for (const auto &rule_ptr : rule_targets) {
                if (overridden_rules.find(rule_ptr.get()) != overridden_rules.end()) {
                    continue;
                }

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
                if (overridden_rules.find(rule_ptr.get()) != overridden_rules.end()) {
                    continue;
                }

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
        rule_filters_.clear();
        input_filters_.clear();
        targets_from_filters_.clear();

        // Then rule filters
        for (const auto &[id, filter] : exclusions_.rule_filters) {
            auto rule_targets = target_to_rules(filter.targets, final_rules_, rules_by_tags_);
            auto filter_ptr = std::make_shared<exclusion::rule_filter>(
                id, filter.conditions, std::move(rule_targets));
            rule_filters_.emplace(filter_ptr->get_id(), filter_ptr);

            for (const auto &cond : filter.conditions) {
                for (const auto &target : cond->get_targets()) {
                    targets_from_filters_.emplace(target.root);
                }
            }
        }

        // Finally input filters
        for (auto &[id, filter] : exclusions_.input_filters) {
            auto rule_targets = target_to_rules(filter.targets, final_rules_, rules_by_tags_);
            auto filter_ptr = std::make_shared<exclusion::input_filter>(
                id, filter.conditions, std::move(rule_targets), filter.filter);
            input_filters_.emplace(filter_ptr->get_id(), filter_ptr);

            for (const auto &cond : filter.conditions) {
                for (const auto &target : cond->get_targets()) {
                    targets_from_filters_.emplace(target.root);
                }
            }
        }
    }

    if ((state & manifest_update) != change_state::none) {
        // Remove unnecessary targets
        std::unordered_set<manifest::target_type> all_targets;
        all_targets.insert(targets_from_rules_.begin(), targets_from_rules_.end());
        all_targets.insert(targets_from_filters_.begin(), targets_from_filters_.end());

        target_manifest_.remove_unused(all_targets);
    }

    auto rs = std::make_shared<ddwaf::ruleset>();
    rs->manifest = target_manifest_;
    rs->insert_rules(final_rules_);
    rs->rule_filters = rule_filters_;
    rs->input_filters = input_filters_;
    rs->free_fn = free_fn_;
    rs->event_obfuscator = event_obfuscator_;

    return rs;
}

builder::change_state builder::load(parameter::map &root, ruleset_info &info)
{
    change_state state = change_state::none;

    auto metadata = parser::at<parameter::map>(root, "metadata", {});
    auto rules_version = metadata.find("rules_version");
    if (rules_version != metadata.end()) {
        info.set_version(rules_version->second);
    }

    auto it = root.find("rules");
    if (it != root.end()) {
        decltype(rule_data_ids_) rule_data_ids;

        parameter::vector rules = it->second;
        auto new_base_rules = parser::v2::parse_rules(rules, info, target_manifest_, rule_data_ids);

        if (new_base_rules.empty()) {
            throw ddwaf::parsing_error("no valid rules found");
        }

        // Upon reaching this stage, we know our base ruleset is valid
        base_rules_ = std::move(new_base_rules);
        rule_data_ids_ = std::move(rule_data_ids);
        state = state | change_state::rules;
    }

    it = root.find("rules_data");
    if (it != root.end()) {
        parameter::vector rules_data = it->second;
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
        parameter::vector overrides = it->second;
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
        parameter::vector exclusions = it->second;
        if (!exclusions.empty()) {
            auto new_exclusions = parser::v2::parse_filters(exclusions, target_manifest_, limits_);

            if (new_exclusions.empty()) {
                // Ignore a non-critical error
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
