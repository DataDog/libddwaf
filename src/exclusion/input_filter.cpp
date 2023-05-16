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
    std::set<rule *> rule_targets, std::shared_ptr<object_filter> filter)
    : id_(std::move(id)), conditions_(std::move(conditions)),
      rule_targets_(std::move(rule_targets)), filter_(std::move(filter))
{}

std::optional<excluded_set> input_filter::match(const object_store &store, cache_type &cache,
    transformer_cache &tcache, ddwaf::timer &deadline) const
{
    if (!cache.result) {
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
            auto opt_match = cond->match(store, {}, run_on_new, {}, tcache, deadline);
            if (!opt_match.has_value()) {
                cache.last_cond = cond_iter;
                return std::nullopt;
            }

            run_on_new = false;
            cond_iter++;
        }

        cache.result = true;
    }

    auto objects = filter_->match(store, cache.object_filter_cache, deadline);

    if (objects.empty()) {
        return std::nullopt;
    }

    return {{rule_targets_, std::move(objects)}};
}

} // namespace ddwaf::exclusion
