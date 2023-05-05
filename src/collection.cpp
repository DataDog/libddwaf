// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <collection.hpp>
#include <exception.hpp>
#include <log.hpp>

namespace ddwaf {

std::optional<event> match_rule(rule *rule, const object_store &store,
    memory::unordered_map<ddwaf::rule *, rule::cache_type> &cache,
    const memory::unordered_set<ddwaf::rule *> &rules_to_exclude,
    const memory::unordered_map<ddwaf::rule *, collection::object_set> &objects_to_exclude,
    const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
    ddwaf::timer &deadline)
{
    const auto &id = rule->get_id();

    if (deadline.expired()) {
        DDWAF_INFO("Ran out of time while running rule %s", id.c_str());
        throw timeout_exception();
    }

    if (!rule->is_enabled()) {
        return std::nullopt;
    }

    if (rules_to_exclude.find(rule) != rules_to_exclude.end()) {
        DDWAF_DEBUG("Excluding Rule %s", id.c_str());
        return std::nullopt;
    }

    DDWAF_DEBUG("Running the WAF on rule %s", id.c_str());

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
            event = rule->match(store, rule_cache, objects_excluded, dynamic_processors, deadline);
        } else {
            event = rule->match(store, rule_cache, {}, dynamic_processors, deadline);
        }

        return event;
    } catch (const ddwaf::timeout_exception &) {
        DDWAF_INFO("Ran out of time while processing %s", id.c_str());
        throw;
    }

    return std::nullopt;
}

template <typename Derived>
void base_collection<Derived>::match(memory::vector<event> &events, const object_store &store,
    collection_cache &cache, const memory::unordered_set<rule *> &rules_to_exclude,
    const memory::unordered_map<rule *, object_set> &objects_to_exclude,
    const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
    ddwaf::timer &deadline) const
{
    if (cache.result >= Derived::type()) {
        return;
    }

    for (auto *rule : rules_) {
        auto event = match_rule(rule, store, cache.rule_cache, rules_to_exclude, objects_to_exclude,
            dynamic_processors, deadline);
        if (event.has_value()) {
            cache.result = Derived::type();
            events.emplace_back(std::move(*event));
            DDWAF_DEBUG("Found event on rule %s", rule->get_id().c_str());
            break;
        }
    }
}

template class base_collection<collection>;
template class base_collection<priority_collection>;

} // namespace ddwaf
