// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include "clock.hpp"
#include "context.hpp"
#include "ddwaf.h"
#include "event.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "module.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "processor/base.hpp"
#include "rule.hpp"
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

struct result_components {
    borrowed_object events;
    borrowed_object actions;
    borrowed_object duration;
    borrowed_object timeout;
    borrowed_object attributes;
    borrowed_object keep;
};

std::pair<owned_object, result_components> initialise_result_object()
{
    auto object = owned_object::make_map({{"events", owned_object::make_array()},
        {"actions", owned_object::make_map()}, {"duration", owned_object::make_unsigned(0)},
        {"timeout", false}, {"attributes", owned_object::make_map()}, {"keep", false}});

    const result_components res{.events = object.at(0),
        .actions = object.at(1),
        .duration = object.at(2),
        .timeout = object.at(3),
        .attributes = object.at(4),
        .keep = object.at(5)};

    return {std::move(object), res};
}

} // namespace

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::pair<DDWAF_RET_CODE, owned_object> context::run(
    owned_object persistent, owned_object ephemeral, uint64_t timeout)
{
    // This scope ensures that all ephemeral and cached objects are removed
    // from the store at the end of the evaluation
    auto store_cleanup_scope = store_.get_eval_scope();
    auto on_exit = scope_exit([this]() { this->exclusion_policy_.ephemeral.clear(); });

    // TODO these checks should be moved to the interface through something along the
    // lines of ctx.insert(...) -> bool
    if (persistent.is_valid() && !store_.insert(std::move(persistent), attribute::none)) {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        return {DDWAF_ERR_INVALID_OBJECT, owned_object{}};
    }

    if (ephemeral.is_valid() && !store_.insert(std::move(ephemeral), attribute::ephemeral)) {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        return {DDWAF_ERR_INVALID_OBJECT, owned_object{}};
    }

    // Generate result object once relevant checks have been made
    auto [result_object, result] = initialise_result_object();
    ddwaf::timer deadline{std::chrono::microseconds(timeout)};

    if (!store_.has_new_targets()) {
        return {DDWAF_OK, std::move(result_object)};
    }

    const event_serializer serializer(event_obfuscator_, actions_);

    std::vector<ddwaf::event> events;
    try {
        eval_preprocessors(result.attributes, deadline);

        // If no rule targets are available, there is no point in evaluating them
        const bool should_eval_rules = check_new_rule_targets();
        const bool should_eval_filters = should_eval_rules || check_new_filter_targets();

        if (should_eval_filters) {
            // Filters need to be evaluated even if rules don't, otherwise it'll
            // break the current condition cache mechanism which requires knowing
            // if an address is new to this run.
            const auto &policy = eval_filters(deadline);

            if (should_eval_rules) {
                eval_rules(policy, events, deadline);
                if (!events.empty()) {
                    set_context_event_address(store_);
                }
            }
        }

        eval_postprocessors(result.attributes, deadline);
        // NOLINTNEXTLINE(bugprone-empty-catch)
    } catch (const ddwaf::timeout_exception &) {}

    serializer.serialize(events, result.events, result.actions);

    // Replacing the object would remove their keys, this won't be an issue
    // once keys and values have been split.
    // TODO: Add helpers to fix this
    result.duration.ref().via.u64 = deadline.elapsed().count();
    result.timeout.ref().via.b8 = deadline.expired_before();

    return {events.empty() ? DDWAF_OK : DDWAF_MATCH, std::move(result_object)};
}

void context::eval_preprocessors(borrowed_object &attributes, ddwaf::timer &deadline)
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

        preproc->eval(store_, attributes, it->second, deadline);
    }
}

void context::eval_postprocessors(borrowed_object &attributes, ddwaf::timer &deadline)
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

        postproc->eval(store_, attributes, it->second, deadline);
    }
}

exclusion::context_policy &context::eval_filters(ddwaf::timer &deadline)
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
        auto exclusion = filter.match(store_, cache, exclusion_matchers_, deadline);
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
        auto exclusion = filter.match(store_, cache, exclusion_matchers_, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                exclusion_policy_.add_input_exclusion(rule, exclusion->objects);
            }
        }
    }

    return exclusion_policy_;
}

void context::eval_rules(const exclusion::context_policy &policy, std::vector<ddwaf::event> &events,
    ddwaf::timer &deadline)
{
    for (std::size_t i = 0; i < ruleset_->rule_modules.size(); ++i) {
        const auto &mod = ruleset_->rule_modules[i];
        auto &cache = rule_module_cache_[i];

        auto verdict = mod.eval(events, store_, cache, policy, rule_matchers_, deadline);
        if (verdict == rule_module::verdict_type::block) {
            break;
        }
    }
}

} // namespace ddwaf
