// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <chrono>
#include <cstdint>
#include <string_view>
#include <vector>

#include "clock.hpp"
#include "context.hpp"
#include "ddwaf.h"
#include "event.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "object_store.hpp"
#include "processor/base.hpp"
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

    ddwaf_object true_obj;
    ddwaf_object_bool(&true_obj, true);
    store.insert(event_addr_idx, event_addr, true_obj, attribute::none);
}

} // namespace

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
DDWAF_RET_CODE context::run(optional_ref<ddwaf_object> persistent,
    optional_ref<ddwaf_object> ephemeral, optional_ref<ddwaf_result> res, uint64_t timeout)
{
    // This scope ensures that all ephemeral and cached objects are removed
    // from the store at the end of the evaluation
    auto store_cleanup_scope = store_.get_eval_scope();
    auto on_exit = scope_exit([this]() { this->exclusion_policy_.ephemeral.clear(); });

    if (res.has_value()) {
        ddwaf_result &output = *res;
        output = DDWAF_RESULT_INITIALISER;
    }

    auto *free_fn = ruleset_->free_fn;
    if (persistent.has_value() && !store_.insert(*persistent, attribute::none, free_fn)) {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        return DDWAF_ERR_INVALID_OBJECT;
    }

    if (ephemeral.has_value() && !store_.insert(*ephemeral, attribute::ephemeral, free_fn)) {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        return DDWAF_ERR_INVALID_OBJECT;
    }

    // If the timeout provided is 0, we need to ensure the parameters are owned
    // by the additive to ensure that the semantics of DDWAF_ERR_TIMEOUT are
    // consistent across all possible timeout scenarios.
    if (timeout == 0) {
        if (res.has_value()) {
            ddwaf_result &output = *res;
            output.timeout = true;
        }
        return DDWAF_OK;
    }

    ddwaf::timer deadline{std::chrono::microseconds(timeout)};

    // If this is a new run but no rule care about those new params, let's skip the run
    if (!store_.has_new_targets()) {
        return DDWAF_OK;
    }

    const event_serializer serializer(*ruleset_->event_obfuscator, *ruleset_->actions);

    optional_ref<ddwaf_object> derived;
    if (res.has_value()) {
        ddwaf_result &output = *res;
        ddwaf_object_map(&output.derivatives);
        derived.emplace(output.derivatives);
    }

    std::vector<ddwaf::event> events;
    try {
        eval_preprocessors(derived, deadline);

        // If no rule targets are available, there is no point in evaluating them
        const bool should_eval_rules = check_new_rule_targets();
        const bool should_eval_filters = should_eval_rules || check_new_filter_targets();

        if (should_eval_filters) {
            // Filters need to be evaluated even if rules don't, otherwise it'll
            // break the current condition cache mechanism which requires knowing
            // if an address is new to this run.
            const auto &policy = eval_filters(deadline);

            if (should_eval_rules) {
                events = eval_rules(policy, deadline);
                if (!events.empty()) {
                    set_context_event_address(store_);
                }
            }
        }

        eval_postprocessors(derived, deadline);
        // NOLINTNEXTLINE(bugprone-empty-catch)
    } catch (const ddwaf::timeout_exception &) {}

    const DDWAF_RET_CODE code = events.empty() ? DDWAF_OK : DDWAF_MATCH;
    if (res.has_value()) {
        ddwaf_result &output = *res;
        serializer.serialize(events, output);
        output.total_runtime = deadline.elapsed().count();
        output.timeout = deadline.expired_before();
    }

    return code;
}

void context::eval_preprocessors(optional_ref<ddwaf_object> &derived, ddwaf::timer &deadline)
{
    DDWAF_DEBUG("Evaluating preprocessors");

    for (const auto &[id, preproc] : ruleset_->preprocessors) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating preprocessors");
            throw timeout_exception();
        }

        auto it = processor_cache_.find(preproc.get());
        if (it == processor_cache_.end()) {
            auto [new_it, res] = processor_cache_.emplace(preproc.get(), processor_cache{});
            it = new_it;
        }

        preproc->eval(store_, derived, it->second, deadline);
    }
}

void context::eval_postprocessors(optional_ref<ddwaf_object> &derived, ddwaf::timer &deadline)
{
    DDWAF_DEBUG("Evaluating postprocessors");

    for (const auto &[id, postproc] : ruleset_->postprocessors) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating postprocessors");
            throw timeout_exception();
        }

        auto it = processor_cache_.find(postproc.get());
        if (it == processor_cache_.end()) {
            auto [new_it, res] = processor_cache_.emplace(postproc.get(), processor_cache{});
            it = new_it;
        }

        postproc->eval(store_, derived, it->second, deadline);
    }
}

exclusion::context_policy &context::eval_filters(ddwaf::timer &deadline)
{
    DDWAF_DEBUG("Evaluating rule filters");

    for (const auto &[id, filter] : ruleset_->rule_filters) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating rule filters");
            throw timeout_exception();
        }

        auto it = rule_filter_cache_.find(filter.get());
        if (it == rule_filter_cache_.end()) {
            auto [new_it, res] =
                rule_filter_cache_.emplace(filter.get(), rule_filter::cache_type{});
            it = new_it;
        }

        rule_filter::cache_type &cache = it->second;
        auto exclusion = filter->match(store_, cache, ruleset_->exclusion_matchers, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                exclusion_policy_.add_rule_exclusion(
                    rule, exclusion->mode, exclusion->action, exclusion->ephemeral);
            }
        }
    }

    DDWAF_DEBUG("Evaluating input filters");

    for (const auto &[id, filter] : ruleset_->input_filters) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating input filters");
            throw timeout_exception();
        }

        auto it = input_filter_cache_.find(filter.get());
        if (it == input_filter_cache_.end()) {
            auto [new_it, res] =
                input_filter_cache_.emplace(filter.get(), input_filter::cache_type{});
            it = new_it;
        }

        input_filter::cache_type &cache = it->second;
        auto exclusion = filter->match(store_, cache, ruleset_->exclusion_matchers, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                exclusion_policy_.add_input_exclusion(rule, exclusion->objects);
            }
        }
    }

    return exclusion_policy_;
}

std::vector<event> context::eval_rules(
    const exclusion::context_policy &policy, ddwaf::timer &deadline)
{
    std::vector<ddwaf::event> events;

    DDWAF_DEBUG("Evaluating rules");
    ruleset_->rules.eval(
        events, store_, collection_cache_, policy, ruleset_->rule_matchers, deadline);

    return events;
}

} // namespace ddwaf
