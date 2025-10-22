// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <memory>

#include "clock.hpp"
#include "condition/base.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"

namespace ddwaf {

bool expression::eval(cache_type &cache, const object_store &store,
    const object_set_ref &objects_excluded, const matcher_mapper &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    if (conditions_.empty()) {
        return true;
    }

    if (expression::get_result(cache)) {
        return true;
    }

    if (cache.conditions.size() < conditions_.size()) {
        cache.conditions.assign(conditions_.size(), condition_cache{});
    }

    for (unsigned i = 0; i < conditions_.size(); ++i) {
        const auto &cond = conditions_[i];
        auto &cond_cache = cache.conditions[i];

        if (cond_cache.match.has_value()) {
            continue;
        }

        if (!cond->eval(cond_cache, store, objects_excluded, dynamic_matchers, deadline)) {
            return false;
        }
    }
    cache.result = true;

    return true;
}

} // namespace ddwaf
