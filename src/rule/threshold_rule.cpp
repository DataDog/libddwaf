// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <chrono>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "clock.hpp"
#include "condition/base.hpp"
#include "ddwaf.h"
#include "event.hpp"
#include "expression.hpp"
#include "iterator.hpp"
#include "object_store.hpp"
#include "rule/threshold_rule.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

std::string filter_with_matcher(const ddwaf_object &src, auto &filter)
{
    if (!filter.transformers.empty()) {
        ddwaf_object dst;
        ddwaf_object_invalid(&dst);

        auto transformed = transformer::manager::transform(src, dst, filter.transformers);
        const scope_exit on_exit([&dst] { ddwaf_object_free(&dst); });
        if (transformed) {
            auto [res, highlight] = filter.matcher->match(dst);
            if (!res) {
                return {};
            }
            return highlight;
        }
    }

    // The value must be filtered
    auto [res, highlight] = filter.matcher->match(src);
    if (!res) {
        // If the matcher fails, there is nothing to filter on
        return {};
    }
    return highlight;
}

const ddwaf_object *get_object(const object_store &store, const auto &filter)
{
    auto [obj, attr] = store.get_target(filter.target);
    if (obj == nullptr) {
        return nullptr;
    }

    if (filter.key_path.empty()) {
        if (obj->type != DDWAF_OBJ_STRING) {
            return nullptr;
        }

        return obj;
    }

    object::value_iterator it{obj, filter.key_path, {}};
    if (!it || it.type() != DDWAF_OBJ_STRING) {
        return nullptr;
    }

    return *it;
}

} // namespace

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
    if (counter_->add_timepoint_and_count(ms)) {
        // Match should be generated differently
        auto matches = expression::get_matches(cache);
        condition_match match{{}, {}, "threshold", threshold_str_, false};
        matches.emplace_back(std::move(match));
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

    const auto *obj = get_object(store, criteria_.filter);
    if (obj == nullptr) {
        return std::nullopt;
    }

    auto res = expr_->eval(cache, store, {}, {}, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());

    std::string filtered_key;
    if (criteria_.filter.matcher) {
        filtered_key = filter_with_matcher(*obj, criteria_.filter);
    } else {
        filtered_key = {obj->stringValue, static_cast<std::size_t>(obj->nbEntries)};
    }

    bool match = false;
    {
        const std::unique_lock<std::mutex> lock{mtx_};
        auto &counter = counter_cache_.emplace_or_retrieve(filtered_key, ms);
        match = counter.add_timepoint_and_count(ms);
    }

    if (match) {
        // Match should be generated differently
        auto matches = expression::get_matches(cache);
        condition_match match{{{"input"sv, object_to_string(*obj), criteria_.filter.name, {}}}, {},
            "threshold", threshold_str_, false};
        matches.emplace_back(std::move(match));
        return {ddwaf::event{this, std::move(matches), false, {}}};
    }

    return std::nullopt;
}

} // namespace ddwaf
