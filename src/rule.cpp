// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "rule.hpp"
#include "timed_counter.hpp"

namespace ddwaf {

std::optional<event> threshold_rule::eval(const object_store &store, cache_type &cache,
    monotonic_clock::time_point now, ddwaf::timer &deadline)
{
    expression::cache_type expr_cache;
    auto res = expr_->eval(expr_cache, store, {}, {}, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    auto count = counter_.add_timepoint_and_count(ms);
    if (count > criteria_.threshold) {
        // Match should be generated differently
        return {ddwaf::event{this, expression::get_matches(cache), res.ephemeral}};
    }

    return std::nullopt;
}

std::optional<event> indexed_threshold_rule::eval(const object_store &store, cache_type &lcache,
    monotonic_clock::time_point now, ddwaf::timer &deadline)
{
    auto [obj, attr] = store.get_target(criteria_.target);
    if (obj == nullptr || obj->type != DDWAF_OBJ_STRING) {
        return std::nullopt;
    }

    expression::cache_type expr_cache;
    auto res = expr_->eval(expr_cache, store, {}, {}, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    std::string_view key{obj->stringValue, static_cast<std::size_t>(obj->nbEntries)};

    auto count = counter_.add_timepoint_and_count(key, ms);
    if (count > criteria_.threshold) {
        // Match should be generated differently
        return {ddwaf::event{this, expression::get_matches(lcache), res.ephemeral}};
    }

    return std::nullopt;
}

} // namespace ddwaf
