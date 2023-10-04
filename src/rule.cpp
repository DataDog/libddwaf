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
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    if (expression::get_result(cache)) {
        // An event was already produced, so we skip the rule
        return std::nullopt;
    }

    auto res = expr_->eval(cache, store, objects_excluded, dynamic_matchers, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    return {ddwaf::event{this, expression::get_matches(cache), res.ephemeral}};
}

} // namespace ddwaf
