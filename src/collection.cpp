// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "compat_memory_resource.hpp"
#include <collection.hpp>
#include <exception.hpp>
#include <log.hpp>
#include <tuple>

namespace ddwaf {

namespace {
std::optional<event> match_rule(const rule::ptr &rule, const object_store &store,
    std::pmr::unordered_map<rule::ptr, rule::cache_type> &cache,
    const std::pmr::unordered_set<ddwaf::rule *> &rules_to_exclude,
    const std::pmr::unordered_map<ddwaf::rule *, collection::object_set> &objects_to_exclude,
    const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
    ddwaf::timer &deadline)
{
    const auto &id = rule->id;

    if (deadline.expired()) {
        DDWAF_INFO("Ran out of time while running rule %s", id.c_str());
        throw timeout_exception();
    }

    if (!rule->is_enabled()) {
        return std::nullopt;
    }

    if (rules_to_exclude.find(rule.get()) != rules_to_exclude.end()) {
        DDWAF_DEBUG("Excluding Rule %s", id.c_str());
        return std::nullopt;
    }

    DDWAF_DEBUG("Running the WAF on rule %s", id.c_str());

    try {
        auto it = cache.find(rule);
        if (it == cache.end()) {
            auto [new_it, res] = cache.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(rule),
                std::forward_as_tuple()); // map forwards allocator
            it = new_it;
        }

        rule::cache_type &rule_cache = it->second;
        std::optional<event> event;
        auto exclude_it = objects_to_exclude.find(rule.get());
        if (exclude_it != objects_to_exclude.end()) {
            const auto &objects_excluded = exclude_it->second;
            event = rule->match(store, rule_cache, objects_excluded, dynamic_processors, deadline);
        } else {
            static const std::pmr::unordered_set<const ddwaf_object *> empty_objects_excluded{
                std::pmr::new_delete_resource()};
            event = rule->match(store, rule_cache, empty_objects_excluded, dynamic_processors, deadline);
        }

        return event;
    } catch (const ddwaf::timeout_exception &) {
        DDWAF_INFO("Ran out of time while processing %s", id.c_str());
        throw;
    }

    return std::nullopt;
}
} // namespace

void collection::match(std::pmr::vector<event> &events,
    std::pmr::unordered_set<std::string_view> & /*seen_actions*/, const object_store &store,
    collection_cache &cache, const std::pmr::unordered_set<rule *> &rules_to_exclude,
    const std::pmr::unordered_map<rule *, object_set> &objects_to_exclude,
    const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
    ddwaf::timer &deadline) const
{
    if (cache.result) {
        return;
    }

    for (const auto &rule : rules_) {
        auto event = match_rule(rule, store, cache.rule_cache, rules_to_exclude, objects_to_exclude,
            dynamic_processors, deadline);
        if (event.has_value()) {
            cache.result = true;
            events.emplace_back(std::move(*event));
            DDWAF_DEBUG("Found event on rule %s", rule->id.c_str());
            break;
        }
    }
}

void priority_collection::match(std::pmr::vector<event> &events,
    std::pmr::unordered_set<std::string_view> &seen_actions, const object_store &store,
    collection_cache &cache, const std::pmr::unordered_set<rule *> &rules_to_exclude,
    const std::pmr::unordered_map<rule *, object_set> &objects_to_exclude,
    const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
    ddwaf::timer &deadline) const
{
    auto &remaining_actions = cache.remaining_actions;
    for (auto it = remaining_actions.begin(); it != remaining_actions.end();) {
        if (seen_actions.find(*it) != seen_actions.end()) {
            it = remaining_actions.erase(it);
        } else {
            ++it;
        }
    }

    // If there are no remaining actions, we treat this collection as a regular one
    if (remaining_actions.empty()) {
        collection::match(events, seen_actions, store, cache, rules_to_exclude, objects_to_exclude,
            dynamic_processors, deadline);
        return;
    }

    // If there are still remaining actions, we treat this collection as a priority tone
    for (const auto &rule : rules_) {
        auto event = match_rule(rule, store, cache.rule_cache, rules_to_exclude, objects_to_exclude,
            dynamic_processors, deadline);
        if (event.has_value()) {
            // If there has been a match, we set the result to true to ensure
            // that the equivalent regular collection doesn't attempt to match
            cache.result = true;

            for (auto &action : event->actions) {
                if (remaining_actions.find(action) != remaining_actions.end()) {
                    remaining_actions.erase(action);
                    seen_actions.emplace(action);
                }
            }
            events.emplace_back(std::move(*event));
            DDWAF_DEBUG("Found event on rule %s", rule->id.c_str());
            if (remaining_actions.empty()) {
                break;
            }
        }
    }
}

} // namespace ddwaf
