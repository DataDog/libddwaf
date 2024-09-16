// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

#include "clock.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/object_filter.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "rule.hpp"
#include "utils.hpp"

namespace ddwaf::exclusion {

using excluded_set = input_filter::excluded_set;

input_filter::input_filter(std::string id, std::shared_ptr<expression> expr,
    std::set<rule *> rule_targets, std::shared_ptr<object_filter> filter)
    : id_(std::move(id)), expr_(std::move(expr)), rule_targets_(std::move(rule_targets)),
      filter_(std::move(filter))
{
    if (!expr_) {
        throw std::invalid_argument("rule filter constructed with null expression");
    }
}

std::optional<excluded_set> input_filter::match(const object_store &store, cache_type &cache,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    const object_limits &limits, ddwaf::timer &deadline) const
{
    DDWAF_DEBUG("Evaluating input filter '{}'", id_);

    // An event was already produced, so we skip the rule
    // Note that conditions in a filter are optional
    auto res = expr_->eval(cache.expr_cache, store, {}, dynamic_matchers, limits, deadline);
    if (!res.outcome) {
        return std::nullopt;
    }

    auto objects =
        filter_->match(store, cache.object_filter_cache, res.ephemeral, limits, deadline);
    if (objects.empty()) {
        return std::nullopt;
    }

    return {{rule_targets_, std::move(objects)}};
}

} // namespace ddwaf::exclusion
