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

#include "builder/action_mapper_builder.hpp"
#include "builder/matcher_builder.hpp"
#include "builder/processor_builder.hpp"
#include "builder/rule_builder.hpp"
#include "configuration/common/configuration.hpp"
#include "exception.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "indexer.hpp"
#include "log.hpp"
#include "ruleset.hpp"
#include "ruleset_builder.hpp"

namespace ddwaf {

namespace {

template <typename T>
std::set<T *> resolve_references(
    const std::vector<reference_spec> &references, const indexer<T> &rules)
{
    std::set<T *> rule_refs;
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

} // namespace

std::shared_ptr<ruleset> ruleset_builder::build(
    const configuration_spec &global_config, change_set current_changes)
{
    constexpr static change_set base_rule_update =
        change_set::rules | change_set::overrides | change_set::actions;
    constexpr static change_set custom_rule_update = change_set::custom_rules | change_set::actions;
    constexpr static change_set filters_update =
        base_rule_update | custom_rule_update | change_set::filters;
    constexpr static change_set processors_update = change_set::processors | change_set::scanners;

    if (!actions_ || (current_changes & change_set::actions) != change_set::none) {
        action_mapper_builder mapper_builder;
        for (const auto &[id, spec] : global_config.actions) {
            mapper_builder.set_action(id, spec.type_str, spec.parameters);
        }
        actions_ = mapper_builder.build_shared();
    }

    // When a configuration with 'rules' or 'rules_override' is received, we
    // need to regenerate the ruleset from the base rules as we want to ensure
    // that there are no side-effects on running contexts.
    if ((current_changes & base_rule_update) != change_set::none) {
        final_base_rules_.clear();

        indexer<rule_builder> rule_builders;
        // Initially, new rules are generated from their spec
        for (const auto &[id, spec] : global_config.base_rules) {
            rule_builders.emplace(std::make_shared<rule_builder>(id, spec));
        }

        // Overrides only impact base rules since user rules can already be modified by the user
        for (const auto &[id, ovrd] : global_config.overrides_by_tags) {
            auto rule_builder_targets = resolve_references(ovrd.targets, rule_builders);
            for (const auto &rule_builder_ptr : rule_builder_targets) {
                rule_builder_ptr->apply_override(ovrd);
            }
        }

        for (const auto &[id, ovrd] : global_config.overrides_by_id) {
            auto rule_builder_targets = resolve_references(ovrd.targets, rule_builders);
            for (const auto &rule_builder_ptr : rule_builder_targets) {
                rule_builder_ptr->apply_override(ovrd);
            }
        }

        for (const auto &builder : rule_builders) {
            if (builder->is_enabled()) {
                final_base_rules_.emplace(builder->build(*actions_));
            }
        }
    }

    if ((current_changes & custom_rule_update) != change_set::none) {
        final_user_rules_.clear();
        // Initially, new rules are generated from their spec
        for (const auto &[id, spec] : global_config.user_rules) {
            rule_builder builder{id, spec};
            if (builder.is_enabled()) {
                final_user_rules_.emplace(builder.build(*actions_));
            }
        }
    }

    // Generate exclusion filters targetting all final rules
    if ((current_changes & filters_update) != change_set::none) {
        rule_filters_.clear();
        input_filters_.clear();

        // First generate rule filters
        for (const auto &[id, filter] : global_config.rule_filters) {
            auto rule_targets = resolve_references(filter.targets, final_base_rules_);
            rule_targets.merge(resolve_references(filter.targets, final_user_rules_));

            auto filter_ptr = std::make_shared<exclusion::rule_filter>(
                id, filter.expr, std::move(rule_targets), filter.on_match, filter.custom_action);
            rule_filters_.emplace(id, filter_ptr);
        }

        // Finally input filters
        for (const auto &[id, filter] : global_config.input_filters) {
            auto rule_targets = resolve_references(filter.targets, final_base_rules_);
            rule_targets.merge(resolve_references(filter.targets, final_user_rules_));

            auto filter_ptr = std::make_shared<exclusion::input_filter>(
                id, filter.expr, std::move(rule_targets), filter.filter);
            input_filters_.emplace(id, filter_ptr);
        }
    }

    // Generate new processors
    if ((current_changes & processors_update) != change_set::none) {
        preprocessors_.clear();
        postprocessors_.clear();

        for (const auto &[id, spec] : global_config.processors) {
            auto proc = processor_builder::build(id, spec, global_config.scanners);
            if (spec.evaluate) {
                preprocessors_.emplace(proc->get_id(), std::move(proc));
            } else {
                postprocessors_.emplace(proc->get_id(), std::move(proc));
            }
        }
    }

    if ((current_changes & change_set::rule_data) != change_set::none) {
        rule_matchers_.clear();
        for (const auto &[id, spec] : global_config.rule_data) {
            rule_matchers_.emplace(id, matcher_builder::build(spec));
        }
    }

    if ((current_changes & change_set::exclusion_data) != change_set::none) {
        exclusion_matchers_.clear();
        for (const auto &[id, spec] : global_config.exclusion_data) {
            exclusion_matchers_.emplace(id, matcher_builder::build(spec));
        }
    }

    auto rs = std::make_shared<ruleset>();
    rs->insert_rules(final_base_rules_.items(), final_user_rules_.items());
    rs->insert_filters(rule_filters_);
    rs->insert_filters(input_filters_);
    rs->insert_preprocessors(preprocessors_);
    rs->insert_postprocessors(postprocessors_);
    rs->rule_matchers = rule_matchers_;
    rs->exclusion_matchers = exclusion_matchers_;
    rs->scanners = global_config.scanners.items();
    rs->actions = actions_;
    rs->free_fn = free_fn_;
    rs->event_obfuscator = event_obfuscator_;

    // An instance is valid if it contains primitives with side-effects, such as
    // rules or postprocessors.
    if (rs->rules.empty() && rs->postprocessors.empty()) {
        DDWAF_WARN("No valid rules or postprocessors found");
        throw parsing_error("no valid or enabled rules or postprocessors found");
    }

    return rs;
}

} // namespace ddwaf
