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

namespace ddwaf {

std::pair<rule_verdict, std::optional<rule_result>> core_rule::match(const object_store &store,
    cache_type &cache, const exclusion::object_set_ref &objects_excluded,
    const matcher_mapper &dynamic_matchers, const object_limits &limits,
    ddwaf::timer &deadline) const
{
    if (expression::get_result(cache)) {
        // An event was already produced, so we skip the rule
        return {verdict_type::none, std::nullopt};
    }

    auto res = expr_->eval(cache, store, objects_excluded, dynamic_matchers, limits, deadline);
    if (!res.outcome) {
        return {verdict_type::none, std::nullopt};
    }

    rule_result result{.keep = contains(flags_, rule_flags::keep_outcome),
        // Rules with no event need not be evaluated again on ephemeral matche
        .ephemeral = res.ephemeral && contains(flags_, rule_flags::generate_event),
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
            .matches = expression::get_matches(cache),
        }};
    }

    return {verdict_, result};
}

} // namespace ddwaf
