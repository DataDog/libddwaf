// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "collection.hpp"
#include "exception.hpp"
#include "exclusion/rule_filter.hpp"
#include "log.hpp"

namespace ddwaf {

std::optional<event> match_rule(rule *rule, const object_store &store,
    memory::unordered_map<ddwaf::rule *, rule::cache_type> &cache,
    const memory::unordered_map<ddwaf::rule *, exclusion::filter_mode> &rules_to_exclude,
    const memory::unordered_map<ddwaf::rule *, collection::object_set> &objects_to_exclude,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline)
{
    const auto &id = rule->get_id();

    if (deadline.expired()) {
        DDWAF_INFO("Ran out of time while evaluating rule '{}'", id);
        throw timeout_exception();
    }

    if (!rule->is_enabled()) {
        DDWAF_DEBUG("Rule '{}' is disabled", id);
        return std::nullopt;
    }

    bool skip_actions = false;
    auto exclude_it = rules_to_exclude.find(rule);
    if (exclude_it != rules_to_exclude.end()) {
        if (exclude_it->second == exclusion::filter_mode::bypass) {
            DDWAF_DEBUG("Bypassing rule '{}'", id);
            return std::nullopt;
        }

        DDWAF_DEBUG("Monitoring rule '{}'", id);
        skip_actions = true;
    }

    DDWAF_DEBUG("Evaluating rule '{}'", id);

    try {
        auto it = cache.find(rule);
        if (it == cache.end()) {
            auto [new_it, res] = cache.emplace(rule, rule::cache_type{});
            it = new_it;
        }

        rule::cache_type &rule_cache = it->second;
        std::optional<event> event;
        auto exclude_it = objects_to_exclude.find(rule);
        if (exclude_it != objects_to_exclude.end()) {
            const auto &objects_excluded = exclude_it->second;
            event = rule->match(store, rule_cache, objects_excluded, dynamic_matchers, deadline);
        } else {
            event = rule->match(store, rule_cache, {}, dynamic_matchers, deadline);
        }

        if (event.has_value() && skip_actions) {
            event->skip_actions = true;
        }

        return event;
    } catch (const ddwaf::timeout_exception &) {
        DDWAF_INFO("Ran out of time while evaluating rule '{}'", id);
        throw;
    }

    return std::nullopt;
}

template <typename Derived>
void base_collection<Derived>::match(std::vector<event> &events, const object_store &store,
    collection_cache &cache,
    const memory::unordered_map<ddwaf::rule *, exclusion::filter_mode> &rules_to_exclude,
    const memory::unordered_map<rule *, collection::object_set> &objects_to_exclude,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    if (cache.result >= Derived::type()) {
        // If the result was cached but ephemeral, clear it. Note that this is
        // just a workaround taking advantage of the order of evaluation of
        // collections. Collections might be removed in the future altogether.
        if (cache.result == Derived::type() && cache.ephemeral) {
            cache.result = collection_type::none;
            cache.ephemeral = false;
        } else {
            return;
        }
    }

    for (auto *rule : rules_) {
        auto event = match_rule(rule, store, cache.rule_cache, rules_to_exclude, objects_to_exclude,
            dynamic_matchers, deadline);
        if (event.has_value()) {
            cache.result = Derived::type();
            cache.ephemeral = event->ephemeral;

            events.emplace_back(std::move(*event));
            DDWAF_DEBUG("Found event on rule {}", rule->get_id());
            break;
        }
    }
}

template class base_collection<collection>;
template class base_collection<priority_collection>;

} // namespace ddwaf
