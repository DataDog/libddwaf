// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "rule.hpp"

namespace ddwaf {

std::optional<event> threshold_rule::eval(const object_store &store, global_cache_type &gcache,
    local_cache_type &lcache, ddwaf::timer &deadline) const
{
    expression::cache_type expr_cache;
    auto res = expr_->eval(expr_cache, store, {}, {}, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    return {ddwaf::event{this, expression::get_matches(lcache), res.ephemeral}};
}

std::optional<event> indexed_threshold_rule::eval(const object_store &store,
    global_cache_type &gcache, local_cache_type &lcache, ddwaf::timer &deadline) const
{
    expression::cache_type expr_cache;
    auto res = expr_->eval(expr_cache, store, {}, {}, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    return {ddwaf::event{this, expression::get_matches(lcache), res.ephemeral}};
}

} // namespace ddwaf
