// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <collection.hpp>
#include <exception.hpp>
#include <log.hpp>

namespace ddwaf {

void collection::match(std::vector<event> &events, const object_store &store,
    const ddwaf::manifest &manifest, cache_type &cache,
    const std::unordered_set<rule::ptr> &rules_to_exclude,
    const std::unordered_map<rule::ptr, object_set> &objects_to_exclude, ddwaf::timer &deadline)
{
    if (cache.result) {
        return;
    }

    for (const auto &rule : rules_) {
        const auto &id = rule->id;

        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while running rule %s", id.c_str());
            throw timeout_exception();
        }

        if (!rule->is_enabled()) {
            continue;
        }

        if (rules_to_exclude.find(rule) != rules_to_exclude.end()) {
            DDWAF_DEBUG("Excluding Rule %s", id.c_str());
            continue;
        }

        DDWAF_DEBUG("Running the WAF on rule %s", id.c_str());

        try {
            auto it = cache.rule_cache.find(rule);
            if (it == cache.rule_cache.end()) {
                auto [new_it, res] = cache.rule_cache.emplace(rule, rule::cache_type{});
                it = new_it;
            }

            rule::cache_type &rule_cache = it->second;
            std::optional<event> event;
            auto exclude_it = objects_to_exclude.find(rule);
            if (exclude_it != objects_to_exclude.end()) {
                const auto &objects_excluded = exclude_it->second;
                event = rule->match(store, manifest, rule_cache, objects_excluded, deadline);
            } else {
                event = rule->match(store, manifest, rule_cache, {}, deadline);
            }

            if (event.has_value()) {
                cache.result = true;
                events.emplace_back(std::move(*event));
                DDWAF_DEBUG("Found event on rule %s", id.c_str());
                break;
            }
        } catch (const ddwaf::timeout_exception &) {
            DDWAF_INFO("Ran out of time while processing %s", id.c_str());
            throw;
        }
    }
}

} // namespace ddwaf
