// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "rule.hpp"
#include "clock.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "utils.hpp"
#include <optional>
#include <utility>
#include <vector>

namespace ddwaf {
namespace {
std::vector<rule_attribute> empty_attributes{};
} // namespace

std::pair<rule_verdict, std::optional<rule_result>> core_rule::match(const object_store &store,
    cache_type &cache, const object_set_ref &objects_excluded,
    const matcher_mapper &dynamic_matchers, evaluation_scope scope, timer &deadline) const
{
    // We don't need to reevaluate the rule if it has already had a  match or,
    // if it's a rule which doesn't generate events, if attributes have already been provided,
    // as pure attribute generation rules need not be reevaluated on subcontext matches.
    if (expression::get_result(cache, scope)) {
        // An event was already produced, so we skip the rule
        return {verdict_type::none, std::nullopt};
    }

    auto res = expr_->eval(cache, store, objects_excluded, dynamic_matchers, scope, deadline);
    if (!res.outcome) {
        return {verdict_type::none, std::nullopt};
    }

    rule_result result{.keep = contains(flags_, rule_flags::keep_outcome),
        .scope =
            contains(flags_, rule_flags::generate_event) ? res.scope : evaluation_scope::context(),
        .action_override = {},
        .actions = actions_,
        .attributes = attributes_};

    if (contains(flags_, rule_flags::generate_event)) {
        result.event = {rule_event{
            .rule{
                .id = id_,
                .name = name_,
                .tags = tags_,
            },
            .matches = expression::get_matches(cache, scope),
        }};
    }

    return {verdict_, result};
}

} // namespace ddwaf
