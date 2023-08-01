// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exclusion/rule_filter.hpp>
#include <log.hpp>

namespace ddwaf::exclusion {

rule_filter::rule_filter(
    std::string id, expression::ptr expr, std::set<rule *> rule_targets, filter_mode mode)
    : id_(std::move(id)), expr_(std::move(expr)), mode_(mode)
{
    rule_targets_.reserve(rule_targets.size());
    for (auto it = rule_targets.begin(); it != rule_targets.end();) {
        rule_targets_.emplace(rule_targets.extract(it++).value());
    }
}

optional_ref<const std::unordered_set<rule *>> rule_filter::match(
    const object_store &store, cache_type &cache, ddwaf::timer &deadline) const
{
    if (expr_) {
        if (expression::get_result(cache)) {
            return std::nullopt;
        }

        if (!expr_->eval(cache, store, {}, {}, deadline)) {
            return std::nullopt;
        }
    }

    return {rule_targets_};
}

} // namespace ddwaf::exclusion
