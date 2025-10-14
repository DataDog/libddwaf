// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include "clock.hpp"
#include "evaluation_engine.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "log.hpp"
#include "module.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "processor/base.hpp"
#include "rule.hpp"
#include "serializer.hpp"
#include "target_address.hpp"
#include "utils.hpp"

namespace ddwaf {

namespace {

// This function adds the waf.context.event "virtual" address, specifically
// meant to be used to tryigger post-processors when there has been an event
// during the lifecycle of the context.
void set_context_event_address(object_store &store)
{
    static const std::string_view event_addr = "waf.context.event";
    static auto event_addr_idx = get_target_index(event_addr);

    if (store.has_target(event_addr_idx)) {
        return;
    }

    store.insert(event_addr_idx, event_addr, owned_object{true});
}

} // namespace

std::pair<bool, owned_object> evaluation_engine::eval(timer &deadline)
{
    // Clear the last batch of targets on exit so that the process can identify
    // new targets in the next eval
    auto on_exit = defer([this]() { store_.clear_last_batch(); });

    result_serializer serializer(ruleset_->obfuscator.get(), *ruleset_->actions, output_alloc_);

    // Generate result object once relevant checks have been made
    auto [result_object, output] = serializer.initialise_result_object();

    if (!store_.has_new_targets()) {
        return {false, std::move(result_object)};
    }

    try {
        // Evaluate preprocessors first in their own try-catch, if there's a
        // timeout we still need to evaluate rules unaffected by it.
        eval_preprocessors(deadline);
        // NOLINTNEXTLINE(bugprone-empty-catch)
    } catch (const ddwaf::timeout_exception &) {}

    std::vector<rule_result> results;

    try {
        // If no rule targets are available, there is no point in evaluating them
        const bool should_eval_rules = check_new_rule_targets();
        const bool should_eval_filters = should_eval_rules || check_new_filter_targets();

        if (should_eval_filters) {
            // Filters need to be evaluated even if rules don't, otherwise it'll
            // break the current condition cache mechanism which requires knowing
            // if an address is new to this run.
            const auto &policy = eval_filters(deadline);

            if (should_eval_rules) {
                eval_rules(policy, results, deadline);
                if (!results.empty()) {
                    set_context_event_address(store_);
                }
            }
        }

        eval_postprocessors(deadline);
        // NOLINTNEXTLINE(bugprone-empty-catch)
    } catch (const ddwaf::timeout_exception &) {}

    // Collect pending attributes, this will check if any new attributes are
    // available (e.g. from a postprocessor) and return a map of all attributes
    // generated during this call.
    // object::assign(result.attributes, collector_.collect_pending(store));
    serializer.serialize(store_, results, collector_, deadline, output);
    return {!output.attributes.empty() || !output.actions.empty() || !output.events.empty(),
        std::move(result_object)};
}

void evaluation_engine::eval_preprocessors(timer &deadline)
{
    DDWAF_DEBUG("Evaluating preprocessors");

    for (const auto &preproc : *ruleset_->preprocessors) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating preprocessors");
            throw timeout_exception();
        }

        auto it = cache_.processors.find(preproc.get());
        if (it == cache_.processors.end()) {
            auto [new_it, res] = cache_.processors.emplace(preproc.get(), processor_cache{});
            it = new_it;
        }

        preproc->eval(store_, collector_, it->second, output_alloc_, deadline);
    }
}

void evaluation_engine::eval_postprocessors(timer &deadline)
{
    DDWAF_DEBUG("Evaluating postprocessors");

    for (const auto &postproc : *ruleset_->postprocessors) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating postprocessors");
            throw timeout_exception();
        }

        auto it = cache_.processors.find(postproc.get());
        if (it == cache_.processors.end()) {
            auto [new_it, res] = cache_.processors.emplace(postproc.get(), processor_cache{});
            it = new_it;
        }

        postproc->eval(store_, collector_, it->second, output_alloc_, deadline);
    }
}

exclusion_policy &evaluation_engine::eval_filters(timer &deadline)
{
    DDWAF_DEBUG("Evaluating rule filters");

    for (const auto &filter : *ruleset_->rule_filters) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating rule filters");
            throw timeout_exception();
        }

        auto it = cache_.rule_filters.find(&filter);
        if (it == cache_.rule_filters.end()) {
            auto [new_it, res] = cache_.rule_filters.emplace(&filter, rule_filter::cache_type{});
            it = new_it;
        }

        rule_filter::cache_type &cache = it->second;
        auto exclusion = filter.match(store_, cache, *ruleset_->exclusion_matchers, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                cache_.exclusions.add_rule_exclusion(rule, exclusion->mode, exclusion->action);
            }
        }
    }

    DDWAF_DEBUG("Evaluating input filters");

    for (const auto &filter : *ruleset_->input_filters) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating input filters");
            throw timeout_exception();
        }

        auto it = cache_.input_filters.find(&filter);
        if (it == cache_.input_filters.end()) {
            auto [new_it, res] = cache_.input_filters.emplace(&filter, input_filter::cache_type{});
            it = new_it;
        }

        input_filter::cache_type &cache = it->second;
        auto exclusion = filter.match(store_, cache, *ruleset_->exclusion_matchers, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                cache_.exclusions.add_input_exclusion(rule, exclusion->objects);
            }
        }
    }

    return cache_.exclusions;
}

void evaluation_engine::eval_rules(
    const exclusion_policy &policy, std::vector<rule_result> &results, timer &deadline)
{
    for (std::size_t i = 0; i < ruleset_->rule_modules.size(); ++i) {
        const auto &mod = ruleset_->rule_modules[i];
        auto &cache = cache_.rule_modules[i];

        auto verdict = mod.eval(results, store_, cache, policy, *ruleset_->rule_matchers, deadline);
        if (verdict == rule_module::verdict_type::block) {
            break;
        }
    }
}

} // namespace ddwaf
