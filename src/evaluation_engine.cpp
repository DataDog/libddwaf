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
using attribute = object_store::attribute;

// This function adds the waf.context.event "virtual" address, specifically
// meant to be used to tryigger post-processors when there has been an event
// during the lifecycle of the context.
// Since post-processors aren't typically used with ephemeral addresses or
// composite requests in general, we don't need to make this address dependent
// on whether the events were ephemeral or not.
void set_context_event_address(object_store &store)
{
    static const std::string_view event_addr = "waf.context.event";
    static auto event_addr_idx = get_target_index(event_addr);

    if (store.has_target(event_addr_idx)) {
        return;
    }

    store.insert(event_addr_idx, event_addr, owned_object{true}, attribute::none);
}

} // namespace

std::pair<bool, owned_object> evaluation_engine::eval(object_store &store, timer &deadline)
{
    // This scope ensures that all ephemeral and cached objects are removed
    // from the store at the end of the evaluation
    auto storecleanup_scope = store.get_eval_scope();
    auto on_exit = scope_exit([this]() { this->exclusion_policy_.ephemeral.clear(); });

    result_serializer serializer(obfuscator_, actions_, output_alloc_);

    // Generate result object once relevant checks have been made
    auto [result_object, output] = serializer.initialise_result_object();

    if (!store.has_new_targets()) {
        return {false, std::move(result_object)};
    }

    try {
        // Evaluate preprocessors first in their own try-catch, if there's a
        // timeout we still need to evaluate rules unaffected by it.
        eval_preprocessors(store, deadline);
        // NOLINTNEXTLINE(bugprone-empty-catch)
    } catch (const ddwaf::timeout_exception &) {}

    std::vector<rule_result> results;

    try {
        // If no rule targets are available, there is no point in evaluating them
        const bool should_eval_rules = check_new_rule_targets(store);
        const bool should_eval_filters = should_eval_rules || check_new_filter_targets(store);

        if (should_eval_filters) {
            // Filters need to be evaluated even if rules don't, otherwise it'll
            // break the current condition cache mechanism which requires knowing
            // if an address is new to this run.
            const auto &policy = eval_filters(store, deadline);

            if (should_eval_rules) {
                eval_rules(store, policy, results, deadline);
                if (!results.empty()) {
                    set_context_event_address(store);
                }
            }
        }

        eval_postprocessors(store, deadline);
        // NOLINTNEXTLINE(bugprone-empty-catch)
    } catch (const ddwaf::timeout_exception &) {}

    // Collect pending attributes, this will check if any new attributes are
    // available (e.g. from a postprocessor) and return a map of all attributes
    // generated during this call.
    // object::assign(result.attributes, collector_.collect_pending(store));
    serializer.serialize(store, results, collector_, deadline, output);
    return {!results.empty(), std::move(result_object)};
}

void evaluation_engine::eval_preprocessors(object_store &store, timer &deadline)
{
    DDWAF_DEBUG("Evaluating preprocessors");

    for (const auto &preproc : preprocessors_) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating preprocessors");
            throw timeout_exception();
        }

        auto it = processor_cache_.find(preproc.get());
        if (it == processor_cache_.end()) {
            auto [new_it, res] = processor_cache_.emplace(preproc.get(), processor_cache{});
            it = new_it;
        }

        preproc->eval(store, collector_, it->second, output_alloc_, deadline);
    }
}

void evaluation_engine::eval_postprocessors(object_store &store, timer &deadline)
{
    DDWAF_DEBUG("Evaluating postprocessors");

    for (const auto &postproc : postprocessors_) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating postprocessors");
            throw timeout_exception();
        }

        auto it = processor_cache_.find(postproc.get());
        if (it == processor_cache_.end()) {
            auto [new_it, res] = processor_cache_.emplace(postproc.get(), processor_cache{});
            it = new_it;
        }

        postproc->eval(store, collector_, it->second, output_alloc_, deadline);
    }
}

exclusion::context_policy &evaluation_engine::eval_filters(object_store &store, timer &deadline)
{
    DDWAF_DEBUG("Evaluating rule filters");

    for (const auto &filter : rule_filters_) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating rule filters");
            throw timeout_exception();
        }

        auto it = rule_filter_cache_.find(&filter);
        if (it == rule_filter_cache_.end()) {
            auto [new_it, res] = rule_filter_cache_.emplace(&filter, rule_filter::cache_type{});
            it = new_it;
        }

        rule_filter::cache_type &cache = it->second;
        auto exclusion = filter.match(store, cache, exclusion_matchers_, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                exclusion_policy_.add_rule_exclusion(
                    rule, exclusion->mode, exclusion->action, exclusion->ephemeral);
            }
        }
    }

    DDWAF_DEBUG("Evaluating input filters");

    for (const auto &filter : input_filters_) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating input filters");
            throw timeout_exception();
        }

        auto it = input_filter_cache_.find(&filter);
        if (it == input_filter_cache_.end()) {
            auto [new_it, res] = input_filter_cache_.emplace(&filter, input_filter::cache_type{});
            it = new_it;
        }

        input_filter::cache_type &cache = it->second;
        auto exclusion = filter.match(store, cache, exclusion_matchers_, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                exclusion_policy_.add_input_exclusion(rule, exclusion->objects);
            }
        }
    }

    return exclusion_policy_;
}

void evaluation_engine::eval_rules(object_store &store, const exclusion::context_policy &policy,
    std::vector<rule_result> &results, timer &deadline)
{
    for (std::size_t i = 0; i < ruleset_->rule_modules.size(); ++i) {
        const auto &mod = ruleset_->rule_modules[i];
        auto &cache = rule_module_cache_[i];

        auto verdict = mod.eval(results, store, cache, policy, rule_matchers_, deadline);
        if (verdict == rule_module::verdict_type::block) {
            break;
        }
    }
}

} // namespace ddwaf
