// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule.hpp>

#include <waf.hpp>

#include "clock.hpp"
#include <exception.hpp>
#include <log.hpp>
#include <memory>

namespace ddwaf {

std::optional<event> rule::match(const object_store &store, cache_type &cache,
    const std::unordered_set<const ddwaf_object *> &objects_excluded,
    const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
    transformer_cache &tcache, ddwaf::timer &deadline) const
{
    // An event was already produced, so we skip the rule
    if (cache.result) {
        return std::nullopt;
    }

    // On the first run, go through the conditions. Stop either at the first
    // condition that didn't match and return no event or go through all
    // and return an event.
    // On subsequent runs, we can start at the first condition that did not
    // match, because if the conditions matched with the data of the first
    // run, then they having new data will make them match again. The condition
    // that failed (and stopped the processing), we can run it again, but only
    // on the new data. The subsequent conditions, we need to run with all data.
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
        auto opt_match =
            cond->match(store, objects_excluded, run_on_new, dynamic_processors, tcache, deadline);
        if (!opt_match.has_value()) {
            cache.last_cond = cond_iter;
            return std::nullopt;
        }
        cache.matches.emplace_back(std::move(*opt_match));

        run_on_new = false;
        cond_iter++;
    }

    cache.result = true;

    ddwaf::event evt{this, std::move(cache.matches)};
    return {std::move(evt)};
}

} // namespace ddwaf
