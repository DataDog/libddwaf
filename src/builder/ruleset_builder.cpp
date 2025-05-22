// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
//
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
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
#include "matcher/base.hpp"
#include "processor/base.hpp"
#include "rule.hpp"
#include "ruleset.hpp"
#include "ruleset_builder.hpp"
#include "scanner.hpp"

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
        for (const auto &[id, rule] : rules) { rule_refs.emplace(rule); }
    }
    return rule_refs;
}

} // namespace

std::shared_ptr<ruleset> ruleset_builder::build(
    const configuration_spec &global_config, change_set current_changes)
{
    constexpr static change_set base_rule_update =
        change_set::rules | change_set::rule_overrides | change_set::actions;
    constexpr static change_set custom_rule_update = change_set::custom_rules | change_set::actions;
    constexpr static change_set filters_update =
        base_rule_update | custom_rule_update | change_set::filters;
    constexpr static change_set processors_update =
        change_set::processors | change_set::scanners | change_set::processor_overrides;

    if (!actions_ || contains(current_changes, change_set::actions)) {
        action_mapper_builder mapper_builder;
        for (const auto &[id, spec] : global_config.actions) {
            mapper_builder.set_action(id, spec.type_str, spec.parameters);
        }
        actions_ = mapper_builder.build_shared();
    }

    // When a configuration with 'rules' or 'rules_override' is received, we
    // need to regenerate the ruleset from the base rules as we want to ensure
    // that there are no side-effects on running contexts.
    if (!final_base_rules_ || contains(current_changes, base_rule_update)) {
        std::vector<rule_builder> rule_builders;
        rule_builders.reserve(global_config.base_rules.size());

        indexer<rule_builder> rule_builder_index;

        // Initially, new rules are generated from their spec
        for (const auto &[id, spec] : global_config.base_rules) {
            rule_builders.emplace_back(id, spec);
            rule_builder_index.emplace(&rule_builders.back());
        }

        // Overrides only impact base rules since user rules can already be modified by the user
        for (const auto &[id, ovrd] : global_config.rule_overrides_by_tags) {
            auto rule_builder_targets = resolve_references(ovrd.targets, rule_builder_index);
            for (const auto &rule_builder_ptr : rule_builder_targets) {
                rule_builder_ptr->apply_override(ovrd);
            }
        }

        for (const auto &[id, ovrd] : global_config.rule_overrides_by_id) {
            auto rule_builder_targets = resolve_references(ovrd.targets, rule_builder_index);
            for (const auto &rule_builder_ptr : rule_builder_targets) {
                rule_builder_ptr->apply_override(ovrd);
            }
        }

        std::vector<core_rule> rules;
        rules.reserve(rule_builders.size());
        for (auto &builder : rule_builders) {
            if (builder.is_enabled()) {
                rules.emplace_back(builder.build(*actions_));
            }
        }
        final_base_rules_ = std::make_shared<const std::vector<core_rule>>(std::move(rules));
    }

    if (!final_user_rules_ || contains(current_changes, custom_rule_update)) {
        // Initially, new rules are generated from their spec
        std::vector<core_rule> rules;
        rules.reserve(global_config.user_rules.size());
        for (const auto &[id, spec] : global_config.user_rules) {
            rule_builder builder{id, spec};
            if (builder.is_enabled()) {
                rules.emplace_back(builder.build(*actions_));
            }
        }
        final_user_rules_ = std::make_shared<const std::vector<core_rule>>(std::move(rules));
    }

    if (contains(current_changes, base_rule_update | custom_rule_update)) {
        rule_index_.clear();
        for (const auto &rule : *final_base_rules_) { rule_index_.emplace(&rule); }
        for (const auto &rule : *final_user_rules_) { rule_index_.emplace(&rule); }
    }

    // Generate rule filters targetting all final rules
    if (!rule_filters_ || contains(current_changes, filters_update)) {
        // First generate rule filters
        std::vector<exclusion::rule_filter> filters;
        filters.reserve(global_config.rule_filters.size());
        for (const auto &[id, filter] : global_config.rule_filters) {
            auto rule_targets = resolve_references(filter.targets, rule_index_);
            filters.emplace_back(
                id, filter.expr, std::move(rule_targets), filter.on_match, filter.custom_action);
        }
        rule_filters_ =
            std::make_shared<const std::vector<exclusion::rule_filter>>(std::move(filters));
    }

    // Generate input filters targetting all final rules
    if (!input_filters_ || contains(current_changes, filters_update)) {
        // Finally input filters
        std::vector<exclusion::input_filter> filters;
        filters.reserve(global_config.input_filters.size());
        for (const auto &[id, filter] : global_config.input_filters) {
            auto rule_targets = resolve_references(filter.targets, rule_index_);
            filters.emplace_back(id, filter.expr, std::move(rule_targets), filter.filter);
        }
        input_filters_ =
            std::make_shared<const std::vector<exclusion::input_filter>>(std::move(filters));
    }

    // Generate new scanners
    if (!scanners_ || contains(current_changes, change_set::scanners)) {
        std::vector<scanner> new_scanners;
        new_scanners.reserve(global_config.scanners.size());
        for (const auto &[id, scnr] : global_config.scanners) { new_scanners.emplace_back(scnr); }

        scanner_index_.clear();
        scanners_ = std::make_shared<const std::vector<scanner>>(std::move(new_scanners));
        for (const auto &scnr : *scanners_) { scanner_index_.emplace(&scnr); }
    }

    // Generate new processors
    if (!preprocessors_ || !postprocessors_ || contains(current_changes, processors_update)) {
        // Generate builders
        std::vector<processor_builder> preproc_builders;
        std::vector<processor_builder> postproc_builders;
        for (const auto &[id, spec] : global_config.processors) {
            if (spec.evaluate) {
                preproc_builders.emplace_back(id, spec);
            } else {
                postproc_builders.emplace_back(id, spec);
            }
        }

        // Since processors don't have tags, we can use a hash table instead
        std::unordered_map<std::string_view, processor_builder *> proc_builder_index;
        proc_builder_index.reserve(preproc_builders.size() + postproc_builders.size());
        for (auto &builder : preproc_builders) {
            proc_builder_index.emplace(builder.get_id(), &builder);
        }
        for (auto &builder : postproc_builders) {
            proc_builder_index.emplace(builder.get_id(), &builder);
        }

        // Apply overrides
        for (const auto &[id, ovrd] : global_config.processor_overrides) {
            for (const auto &target : ovrd.targets) {
                auto builder_it = proc_builder_index.find(target.ref_id);
                if (builder_it != proc_builder_index.end()) {
                    builder_it->second->apply_override(ovrd);
                }
            }
        }

        std::vector<std::unique_ptr<base_processor>> preprocessors;
        std::vector<std::unique_ptr<base_processor>> postprocessors;

        preprocessors.reserve(preproc_builders.size());
        postprocessors.reserve(postproc_builders.size());

        for (auto &builder : preproc_builders) {
            preprocessors.emplace_back(builder.build(scanner_index_));
        }
        for (auto &builder : postproc_builders) {
            postprocessors.emplace_back(builder.build(scanner_index_));
        }

        preprocessors_ = std::make_shared<const std::vector<std::unique_ptr<base_processor>>>(
            std::move(preprocessors));
        postprocessors_ = std::make_shared<const std::vector<std::unique_ptr<base_processor>>>(
            std::move(postprocessors));
    }

    if (!rule_matchers_ || contains(current_changes, change_set::rule_data)) {
        matcher_mapper matchers;
        matchers.reserve(global_config.rule_data.size());
        for (const auto &[id, spec] : global_config.rule_data) {
            matchers.emplace(id, matcher_builder::build(spec));
        }
        rule_matchers_ = std::make_shared<matcher_mapper>(std::move(matchers));
    }

    if (!exclusion_matchers_ || contains(current_changes, change_set::exclusion_data)) {
        matcher_mapper matchers;
        matchers.reserve(global_config.rule_data.size());
        for (const auto &[id, spec] : global_config.exclusion_data) {
            matchers.emplace(id, matcher_builder::build(spec));
        }
        exclusion_matchers_ = std::make_shared<matcher_mapper>(std::move(matchers));
    }

    auto rs = std::make_shared<ruleset>();
    rs->insert_rules(final_base_rules_, final_user_rules_);
    rs->insert_filters(rule_filters_);
    rs->insert_filters(input_filters_);
    rs->insert_preprocessors(preprocessors_);
    rs->insert_postprocessors(postprocessors_);
    rs->rule_matchers = rule_matchers_;
    rs->exclusion_matchers = exclusion_matchers_;
    rs->scanners = scanners_;
    rs->actions = actions_;
    rs->free_fn = free_fn_;
    rs->obfuscator = obfuscator_;

    // An instance is valid if it contains primitives with side-effects, such as
    // rules or postprocessors.
    if (rs->base_rules->empty() && rs->user_rules->empty() && rs->postprocessors->empty()) {
        DDWAF_WARN("No valid rules or postprocessors found");
        throw incomplete_ruleset();
    }

    return rs;
}

} // namespace ddwaf
