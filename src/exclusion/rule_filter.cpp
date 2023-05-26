// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exclusion/rule_filter.hpp>
#include <log.hpp>

namespace ddwaf::exclusion {

rule_filter::rule_filter(
    std::string id, std::vector<condition::ptr> conditions, std::set<rule *> rule_targets)
    : id_(std::move(id)), conditions_(std::move(conditions))
{
    rule_targets_.reserve(rule_targets.size());
    for (auto it = rule_targets.begin(); it != rule_targets.end();) {
        rule_targets_.emplace(rule_targets.extract(it++).value());
    }
}

optional_ref<const std::unordered_set<rule *>> rule_filter::match(
    const object_store &store, cache_type &cache, ddwaf::timer &deadline) const
{
    if (cache.result) {
        return {};
    }

    std::vector<condition::ptr>::const_iterator cond_iter;
    bool run_on_new;
    if (cache.last_cond.has_value()) {
        cond_iter = *cache.last_cond;
        run_on_new = true;
    } else {
        cond_iter = conditions_.cbegin();
        run_on_new = false;
    }

    while (cond_iter != conditions_.cend()) {
        auto &&cond = *cond_iter;
        // TODO: Condition interface without events
        auto opt_match = cond->match(store, {}, run_on_new, {}, deadline);
        if (!opt_match.has_value()) {
            cache.last_cond = cond_iter;
            return {};
        }

        run_on_new = false;
        cond_iter++;
    }

    cache.result = true;

    return {rule_targets_};
}

} // namespace ddwaf::exclusion
