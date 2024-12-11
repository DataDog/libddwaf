// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
//
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "action_mapper.hpp"
#include "builder/processor_builder.hpp"
#include "configuration/common/configuration.hpp"
#include "exception.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "indexer.hpp"
#include "log.hpp"
#include "rule.hpp"
#include "ruleset.hpp"
#include "ruleset_builder.hpp"

namespace ddwaf {

namespace {

std::set<core_rule *> references_to_rules(
    const std::vector<reference_spec> &references, const indexer<core_rule> &rules)
{
    std::set<core_rule *> rule_refs;
    if (!references.empty()) {
        for (const auto &ref : references) {
            if (ref.type == reference_type::id) {
                auto *rule = rules.find_by_id(ref.ref_id);
                if (rule == nullptr) {
                    continue;
                }
                rule_refs.emplace(rule);
            } else if (ref.type == reference_type::tags) {
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

core_rule::verdict_type obtain_rule_verdict(
    const action_mapper &mapper, const std::vector<std::string> &rule_actions)
{
    for (const auto &action : rule_actions) {
        auto it = mapper.find(action);
        if (it == mapper.end()) {
            continue;
        }

        auto action_mode = it->second.type;
        if (is_blocking_action(action_mode)) {
            return core_rule::verdict_type::block;
        }
    }
    return core_rule::verdict_type::monitor;
}

} // namespace

std::shared_ptr<ruleset> ruleset_builder::build(merged_configuration_spec &config)
{
    constexpr static change_set base_rule_update =
        change_set::rules | change_set::overrides | change_set::actions;
    constexpr static change_set custom_rule_update = change_set::custom_rules | change_set::actions;
    constexpr static change_set filters_update =
        base_rule_update | custom_rule_update | change_set::filters;
    constexpr static change_set processors_update = change_set::processors | change_set::scanners;

    if (!actions_ || (config.content & change_set::actions) != change_set::none) {
        action_mapper_builder mapper_builder;
        for (const auto &spec : config.actions) {
            mapper_builder.set_action(spec.id, spec.type_str, spec.parameters);
        }
        actions_ = mapper_builder.build_shared();
    }

    // When a configuration with 'rules' or 'rules_override' is received, we
    // need to regenerate the ruleset from the base rules as we want to ensure
    // that there are no side-effects on running contexts.
    if ((config.content & base_rule_update) != change_set::none) {
        final_base_rules_.clear();

        // Initially, new rules are generated from their spec
        for (const auto &spec : config.base_rules) {
            auto rule_ptr = std::make_shared<core_rule>(
                spec.id, spec.name, spec.tags, spec.expr, spec.actions, spec.enabled, spec.source);
            final_base_rules_.emplace(rule_ptr);
        }

        // Overrides only impact base rules since user rules can already be modified by the user
        for (const auto &ovrd : config.overrides_by_tags) {
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

        for (const auto &ovrd : config.overrides_by_id) {
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

        // Update blocking mode and remove any disabled rules
        for (auto it = final_base_rules_.begin(); it != final_base_rules_.end();) {
            if (!(*it)->is_enabled()) {
                it = final_base_rules_.erase(it);
                continue;
            }

            auto mode = obtain_rule_verdict(*actions_, (*it)->get_actions());
            (*it)->set_verdict(mode);

            ++it;
        }
    }

    if ((config.content & custom_rule_update) != change_set::none) {
        final_user_rules_.clear();
        // Initially, new rules are generated from their spec
        for (const auto &spec : config.user_rules) {
            auto mode = obtain_rule_verdict(*actions_, spec.actions);
            auto rule_ptr = std::make_shared<core_rule>(spec.id, spec.name, spec.tags, spec.expr,
                spec.actions, spec.enabled, spec.source, mode);
            if (!rule_ptr->is_enabled()) {
                // Skip disabled rules
                continue;
            }
            final_user_rules_.emplace(rule_ptr);
        }
    }

    // Generate exclusion filters targetting all final rules
    if ((config.content & filters_update) != change_set::none) {
        rule_filters_.clear();
        input_filters_.clear();

        // First generate rule filters
        for (const auto &filter : config.rule_filters) {
            auto rule_targets = references_to_rules(filter.targets, final_base_rules_);
            rule_targets.merge(references_to_rules(filter.targets, final_user_rules_));

            auto filter_ptr = std::make_shared<exclusion::rule_filter>(filter.id, filter.expr,
                std::move(rule_targets), filter.on_match, filter.custom_action);
            rule_filters_.emplace(filter_ptr->get_id(), filter_ptr);
        }

        // Finally input filters
        for (const auto &filter : config.input_filters) {
            auto rule_targets = references_to_rules(filter.targets, final_base_rules_);
            rule_targets.merge(references_to_rules(filter.targets, final_user_rules_));

            auto filter_ptr = std::make_shared<exclusion::input_filter>(
                filter.id, filter.expr, std::move(rule_targets), filter.filter);
            input_filters_.emplace(filter_ptr->get_id(), filter_ptr);
        }
    }

    // Generate new processors
    if ((config.content & processors_update) != change_set::none) {
        preprocessors_.clear();
        postprocessors_.clear();

        for (auto &spec : config.processors) {
            auto proc = processor_builder::build(spec, config.scanners);
            if (spec.evaluate) {
                preprocessors_.emplace(proc->get_id(), std::move(proc));
            } else {
                postprocessors_.emplace(proc->get_id(), std::move(proc));
            }
        }
    }

    auto rs = std::make_shared<ruleset>();
    rs->insert_rules(final_base_rules_.items(), final_user_rules_.items());
    rs->insert_filters(rule_filters_);
    rs->insert_filters(input_filters_);
    rs->insert_preprocessors(preprocessors_);
    rs->insert_postprocessors(postprocessors_);
    // rs->rule_matchers = rule_matchers_;
    // rs->exclusion_matchers = exclusion_matchers_;
    rs->scanners = config.scanners.items();
    rs->actions = actions_;
    rs->free_fn = free_fn_;
    rs->event_obfuscator = event_obfuscator_;

    // Since disabled rules aren't added to the final ruleset, we must check
    // again that there are rules available.
    if (rs->rules.empty()) {
        DDWAF_WARN("No valid rules found");
        throw parsing_error("no valid or enabled rules found");
    }

    return rs;
}

} // namespace ddwaf
