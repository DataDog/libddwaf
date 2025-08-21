// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

#include "clock.hpp"
#include "exclusion/common.hpp"
#include "exclusion/rule_filter.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "rule.hpp"
#include "utils.hpp"

namespace ddwaf::exclusion {

using excluded_set = rule_filter::excluded_set;

rule_filter::rule_filter(std::string id, std::shared_ptr<expression> expr,
    std::set<const core_rule *> rule_targets, filter_mode mode, std::string action)
    : id_(std::move(id)), expr_(std::move(expr)), mode_(mode), action_(std::move(action))
{
    if (!expr_) {
        throw std::invalid_argument("rule filter constructed with null expression");
    }

    rule_targets_.reserve(rule_targets.size());
    for (auto it = rule_targets.begin(); it != rule_targets.end();) {
        rule_targets_.emplace(rule_targets.extract(it++).value());
    }
}

std::optional<excluded_set> rule_filter::match(const object_store &store, cache_type &cache,
    const matcher_mapper &dynamic_matchers, ddwaf::timer &deadline) const
{
    DDWAF_DEBUG("Evaluating rule filter '{}'", id_);

    // Don't return a match again if we already did
    if (expression::get_result(cache)) {
        return std::nullopt;
    }

    auto res = expr_->eval(cache, store, {}, dynamic_matchers, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    return {{.rules = rule_targets_, .scope = res.scope, .mode = mode_, .action = action_}};
}

} // namespace ddwaf::exclusion
