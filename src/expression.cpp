// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <charconv>
#include <iostream>
#include <memory>
#include <variant>

#include "event.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

namespace ddwaf {

eval_result expression::eval(cache_type &cache, const object_store &store,
    const exclusion::object_set_ref &objects_excluded,
    const boost::unordered_flat_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    if (cache.result || conditions_.empty()) {
        return {true, false};
    }

    if (cache.conditions.size() < conditions_.size()) {
        cache.conditions.assign(conditions_.size(), condition_cache{});
    }

    bool ephemeral_match = false;
    for (unsigned i = 0; i < conditions_.size(); ++i) {
        const auto &cond = conditions_[i];
        auto &cond_cache = cache.conditions[i];

        if (cond_cache.match.has_value() && !cond_cache.match->ephemeral) {
            continue;
        }

        auto [res, ephemeral] =
            cond->eval(cond_cache, store, objects_excluded, dynamic_matchers, deadline);
        if (!res) {
            return {false, false};
        }
        ephemeral_match = ephemeral_match || ephemeral;
    }
    cache.result = !ephemeral_match;

    return {true, ephemeral_match};
}

} // namespace ddwaf
