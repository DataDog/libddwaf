// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "rule/threshold_rule.hpp"
#include <variant>

using namespace std::literals;

namespace ddwaf {

std::optional<event> threshold_rule::eval(const object_store &store, cache_type &cache,
    monotonic_clock::time_point now, ddwaf::timer &deadline)
{
    if (expression::get_result(cache)) {
        // An event was already produced, so we skip the rule
        return std::nullopt;
    }

    auto res = expr_->eval(cache, store, {}, {}, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    auto count = counter_->add_timepoint_and_count(ms);
    if (count > criteria_.threshold) {
        // Match should be generated differently
        // Match should be generated differently
        auto matches = expression::get_matches(cache);
        matches.emplace_back(condition_match{{}, {}, "threshold", threshold_str_, false});
        return {ddwaf::event{this, std::move(matches), false, {}}};
    }

    return std::nullopt;
}

std::optional<event> indexed_threshold_rule::eval(const object_store &store, cache_type &cache,
    monotonic_clock::time_point now, ddwaf::timer &deadline)
{
    if (expression::get_result(cache)) {
        // An event was already produced, so we skip the rule
        return std::nullopt;
    }

    auto [obj, attr] = store.get_target(criteria_.filter.target);
    if (obj == nullptr || obj->type != DDWAF_OBJ_STRING) {
        return std::nullopt;
    }

    auto res = expr_->eval(cache, store, {}, {}, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());

    std::string filtered_key;
    if (criteria_.filter.matcher) {
        // The value must be filtered
        auto [res, highlight] = criteria_.filter.matcher->match(*obj);
        if (!res) {
            // If the matcher fails, there is nothing to filter on
            return std::nullopt;
        }

        filtered_key = std::move(highlight);
    }

    uint64_t count = 0;
    if (filtered_key.empty()) {
        std::string_view key{obj->stringValue, static_cast<std::size_t>(obj->nbEntries)};
        count = counter_->add_timepoint_and_count(key, ms);
    } else {
        count = counter_->add_timepoint_and_count(std::move(filtered_key), ms);
    }

    if (count > criteria_.threshold) {
        // Match should be generated differently
        auto matches = expression::get_matches(cache);
        matches.emplace_back(
            condition_match{{{"input"sv, object_to_string(*obj), criteria_.filter.name, {}}}, {},
                "threshold", threshold_str_, false});
        return {ddwaf::event{this, std::move(matches), false, {}}};
    }

    return std::nullopt;
}

} // namespace ddwaf
