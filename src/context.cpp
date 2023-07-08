// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <log.hpp>

#include <context.hpp>
#include <exception.hpp>
#include <tuple>
#include <unordered_set>
#include <utils.hpp>
#include <waf.hpp>

namespace ddwaf {

DDWAF_RET_CODE context::run(
    ddwaf_object &newParameters, optional_ref<ddwaf_result> res, uint64_t timeout)
{
    if (res.has_value()) {
        ddwaf_result &output = *res;
        output = DDWAF_RESULT_INITIALISER;
    }

    if (!store_.insert(newParameters)) {
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
    if (!is_first_run() && !store_.has_new_targets()) {
        return DDWAF_OK;
    }

    const event_serializer serializer(*ruleset_->event_obfuscator);

    memory::vector<ddwaf::event> events;
    try {
        const auto &rules_to_exclude = filter_rules(deadline);
        const auto &objects_to_exclude = filter_inputs(rules_to_exclude, deadline);
        events = match(rules_to_exclude, objects_to_exclude, deadline);
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

const memory::unordered_set<rule *> &context::filter_rules(ddwaf::timer &deadline)
{
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
            for (auto &&rule : exclusion->get()) { rules_to_exclude_.insert(rule); }
        }
    }
    return rules_to_exclude_;
}

const memory::unordered_map<rule *, context::object_set> &context::filter_inputs(
    const memory::unordered_set<rule *> &rules_to_exclude, ddwaf::timer &deadline)
{
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
                if (rules_to_exclude.find(rule) != rules_to_exclude.end()) {
                    continue;
                }

                auto &common_exclusion = objects_to_exclude_[rule];
                common_exclusion.insert(exclusion->objects.begin(), exclusion->objects.end());
            }
        }
    }

    return objects_to_exclude_;
}

memory::vector<event> context::match(const memory::unordered_set<rule *> &rules_to_exclude,
    const memory::unordered_map<rule *, object_set> &objects_to_exclude, ddwaf::timer &deadline)
{
    memory::vector<ddwaf::event> events;

    auto eval_collection = [&](const auto &type, const auto &collection) {
        auto it = collection_cache_.find(type);
        if (it == collection_cache_.end()) {
            auto [new_it, res] = collection_cache_.emplace(type, collection_cache{});
            it = new_it;
        }
        collection.match(events, store_, it->second, rules_to_exclude, objects_to_exclude,
            ruleset_->dynamic_processors, deadline);
    };

    // Evaluate user priority collections first
    for (auto &[type, collection] : ruleset_->user_priority_collections) {
        DDWAF_DEBUG("Evaluating user priority collection %.*s", static_cast<int>(type.length()),
            type.data());
        eval_collection(type, collection);
    }

    // Evaluate priority collections first
    for (auto &[type, collection] : ruleset_->base_priority_collections) {
        DDWAF_DEBUG(
            "Evaluating priority collection %.*s", static_cast<int>(type.length()), type.data());
        eval_collection(type, collection);
    }

    // Evaluate regular collection after
    for (auto &[type, collection] : ruleset_->user_collections) {
        DDWAF_DEBUG(
            "Evaluating user collection %.*s", static_cast<int>(type.length()), type.data());
        eval_collection(type, collection);
    }

    // Evaluate regular collection after
    for (auto &[type, collection] : ruleset_->base_collections) {
        DDWAF_DEBUG(
            "Evaluating base collection %.*s", static_cast<int>(type.length()), type.data());
        eval_collection(type, collection);
    }

    return events;
}

} // namespace ddwaf
