// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exclusion/input_filter.hpp>
#include <log.hpp>

namespace ddwaf::exclusion {

using excluded_set = input_filter::excluded_set;

input_filter::input_filter(std::string id, std::vector<condition::ptr> conditions,
    std::set<rule::ptr> rule_targets, object_filter filter)
    : id_(std::move(id)), conditions_(std::move(conditions)),
      rule_targets_(std::move(rule_targets)), filter_(std::move(filter))
{
    for (auto &cond : conditions_) {
        const auto &cond_targets = cond->get_targets();
        targets_.insert(cond_targets.begin(), cond_targets.end());
    }
}

std::optional<excluded_set> input_filter::match(const object_store &store,
    const ddwaf::manifest &manifest, cache_type &cache, ddwaf::timer &deadline) const
{
    if (!cache.result) {
        for (const auto &cond : conditions_) {
            // If there's a (false) cache hit, we only need to run this condition
            // on new parameters.
            bool run_on_new = false;
            auto cached_result = cache.conditions.find(cond);
            if (cached_result != cache.conditions.end()) {
                if (cached_result->second) {
                    continue;
                }
                run_on_new = true;
            } else {
                auto [it, res] = cache.conditions.emplace(cond, false);
                cached_result = it;
            }

            // TODO: Condition interface without events
            auto opt_match = cond->match(store, manifest, {}, run_on_new, deadline);
            if (!opt_match.has_value()) {
                cached_result->second = false;
                return std::nullopt;
            }
            cached_result->second = true;
        }

        cache.result = true;
    }

    auto objects = filter_.match(store, cache.object_filter_cache, deadline);

    if (objects.empty()) {
        return std::nullopt;
    }

    return {{rule_targets_, std::move(objects)}};
}

} // namespace ddwaf::exclusion
