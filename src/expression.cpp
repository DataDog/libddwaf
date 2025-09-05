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
#include "utils.hpp"

namespace ddwaf {

eval_result expression::eval(cache_type &cache, const object_store &store,
    const exclusion::object_set_ref &objects_excluded, const matcher_mapper &dynamic_matchers,
    evaluation_scope scope, ddwaf::timer &deadline) const
{
    if (conditions_.empty()) {
        // Since there's no conditions, we use the default (context) scope
        return {.outcome = true, .scope = {}};
    }

    if (expression::get_result(cache, scope)) {
        return {.outcome = true, .scope = scope};
    }

    if (cache.conditions.size() < conditions_.size()) {
        cache.conditions.assign(conditions_.size(), condition_cache{});
    }

    evaluation_scope final_scope;
    for (unsigned i = 0; i < conditions_.size(); ++i) {
        const auto &cond = conditions_[i];
        auto &cond_cache = cache.conditions[i];

        if (cond_cache.match.has_value() &&
            cond_cache.match->scope.has_higher_precedence_or_is_equal_to(scope)) {
            continue;
        }

        auto [res, cond_eval_scope] =
            cond->eval(cond_cache, store, objects_excluded, dynamic_matchers, deadline);
        if (!res) {
            return {.outcome = false, .scope = {}};
        }

        if (cond_eval_scope.is_subcontext()) {
            final_scope = cond_eval_scope;
        }
    }
    cache.result = true;
    cache.scope = final_scope;

    return {.outcome = true, .scope = final_scope};
}

} // namespace ddwaf
