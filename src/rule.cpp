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
    ddwaf::timer &deadline) const
{
    // An event was already produced, so we skip the rule
    if (cache.result || !expression_->eval(cache.expr_cache, store, objects_excluded,
                            dynamic_processors, deadline)) {
        return std::nullopt;
    }

    cache.result = true;

    ddwaf::event evt{this, expression_->get_matches(cache.expr_cache)};
    return {std::move(evt)};
}

} // namespace ddwaf
