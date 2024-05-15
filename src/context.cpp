// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "context.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "utils.hpp"
#include <memory_resource>

namespace ddwaf {

using attribute = object_store::attribute;

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
DDWAF_RET_CODE context::run(optional_ref<ddwaf_object> persistent,
    optional_ref<ddwaf_object> ephemeral, optional_ref<ddwaf_result> res,
    std::pmr::memory_resource *alloc, uint64_t timeout)
{
    // This scope ensures that all ephemeral and cached objects are removed
    // from the store at the end of the evaluation
    auto store_cleanup_scope = store_.get_eval_scope();
    auto on_exit = scope_exit([this]() { this->exclusion_policy_.ephemeral.clear(); });

    if (persistent.has_value()) {
        owned_object owned{reinterpret_cast<detail::object &>(persistent->get()), alloc};
        if (!store_.insert(std::move(owned), attribute::none)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return DDWAF_ERR_INVALID_OBJECT;
        }
    }

    if (ephemeral.has_value()) {
        owned_object owned{reinterpret_cast<detail::object &>(ephemeral->get()), alloc};
        if (!store_.insert(std::move(owned), attribute::ephemeral)) {
            DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
            return DDWAF_ERR_INVALID_OBJECT;
        }
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
    if (!is_first_run() && !store_.has_new_targets()) {
        return DDWAF_OK;
    }

    const event_serializer serializer(*ruleset_->event_obfuscator, *ruleset_->actions);

    optional_ref<ddwaf_object> derived;
    if (res.has_value()) {
        ddwaf_result &output = *res;
        ddwaf_object_set_map(&output.derivatives, 32, nullptr);
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
            }
        }

        eval_postprocessors(derived, deadline);
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
            auto [new_it, res] = processor_cache_.emplace(preproc.get(), processor::cache_type{});
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
            auto [new_it, res] = processor_cache_.emplace(postproc.get(), processor::cache_type{});
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
        auto exclusion = filter->match(store_, cache, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                exclusion_policy_.add_rule_exclusion(rule, exclusion->mode, exclusion->ephemeral);
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
        auto exclusion = filter->match(store_, cache, deadline);
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

    auto eval_collection = [&](const auto &type, const auto &collection) {
        auto it = collection_cache_.find(type);
        if (it == collection_cache_.end()) {
            auto [new_it, res] = collection_cache_.emplace(type, collection_cache{});
            it = new_it;
        }
        collection.match(events, store_, it->second, policy, ruleset_->dynamic_matchers, deadline);
    };

    // Evaluate user priority collections first
    for (auto &[type, collection] : ruleset_->user_priority_collections) {
        DDWAF_DEBUG("Evaluating user priority collection '{}'", type);
        eval_collection(type, collection);
    }

    // Evaluate priority collections first
    for (auto &[type, collection] : ruleset_->base_priority_collections) {
        DDWAF_DEBUG("Evaluating priority collection '{}'", type);
        eval_collection(type, collection);
    }

    // Evaluate regular collection after
    for (auto &[type, collection] : ruleset_->user_collections) {
        DDWAF_DEBUG("Evaluating user collection '{}'", type);
        eval_collection(type, collection);
    }

    // Evaluate regular collection after
    for (auto &[type, collection] : ruleset_->base_collections) {
        DDWAF_DEBUG("Evaluating base collection '{}'", type);
        eval_collection(type, collection);
    }

    return events;
}

} // namespace ddwaf
