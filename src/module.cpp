// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <module.hpp>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "clock.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "rule.hpp"

namespace ddwaf {

namespace {
using verdict_type = rule_module::verdict_type;

std::pair<verdict_type, std::optional<rule_result>> eval_rule(const core_rule &rule,
    const object_store &store, core_rule::cache_type &cache,
    const exclusion::exclusion_policy &policy, const matcher_mapper &dynamic_matchers,
    ddwaf::timer &deadline)
{
    const auto &id = rule.get_id();

    if (deadline.expired()) {
        DDWAF_INFO("Ran out of time while evaluating rule '{}'", id);
        throw timeout_exception();
    }

    if (!rule.is_enabled()) {
        DDWAF_DEBUG("Rule '{}' is disabled", id);
        return {verdict_type::none, std::nullopt};
    }

    std::string_view action_override;
    auto exclusion = policy.find(&rule);
    if (exclusion.mode == exclusion::filter_mode::bypass) {
        DDWAF_DEBUG("Bypassing rule '{}'", id);
        return {verdict_type::none, std::nullopt};
    }

    rule_verdict verdict_override = rule_verdict::none;
    if (exclusion.mode == exclusion::filter_mode::monitor) {
        action_override = "monitor";
        verdict_override = verdict_type::monitor;
        DDWAF_DEBUG("Monitoring rule '{}'", id);
    } else if (exclusion.mode == exclusion::filter_mode::custom) {
        action_override = exclusion.action_override;
        verdict_override = verdict_type::block;
        DDWAF_DEBUG("Evaluating rule '{}' with custom action '{}'", id, action_override);
    } else {
        DDWAF_DEBUG("Evaluating rule '{}'", id);
    }

    try {
        auto [verdict, outcome] =
            rule.match(store, cache, exclusion.objects, dynamic_matchers, deadline);

        if (outcome.has_value()) {
            outcome->action_override = action_override;
        }

        if (verdict_override != rule_verdict::none) {
            verdict = verdict_override;
        }

        return {verdict, outcome};
    } catch (const ddwaf::timeout_exception &) {
        DDWAF_INFO("Ran out of time while evaluating rule '{}'", id);
        throw;
    }

    return {verdict_type::none, std::nullopt};
}

} // namespace

ddwaf::timer &rule_module::get_deadline(ddwaf::timer &deadline) const
{
    static auto no_deadline = endless_timer();
    return may_expire() ? deadline : no_deadline;
}

verdict_type rule_module::eval_with_collections(std::vector<rule_result> &results,
    object_store &store, cache_type &cache, const exclusion::exclusion_policy &exclusion,
    const matcher_mapper &dynamic_matchers, ddwaf::timer &deadline) const
{
    verdict_type final_verdict = verdict_type::none;
    for (const auto &collection : collections_) {
        DDWAF_DEBUG("Evaluating collection: {}", collection.name);
        auto &collection_cache = cache.collections[collection.name];
        if (collection_cache.type >= collection.type) {
            continue;
        }

        for (std::size_t i = collection.begin; i < collection.end; ++i) {
            const auto &rule = *rules_[i];
            auto [verdict, outcome] =
                eval_rule(rule, store, cache.rules[i], exclusion, dynamic_matchers, deadline);
            if (outcome.has_value()) {
                collection_cache.type = verdict;
                collection_cache.scope = outcome->scope;

                results.emplace_back(std::move(*outcome));
                DDWAF_DEBUG("Found event on rule {}", rule.get_id());

                if (verdict == verdict_type::block) {
                    return verdict_type::block;
                }

                final_verdict = verdict_type::monitor;
                break;
            }
        }
    }
    return final_verdict;
}

verdict_type rule_module::eval(std::vector<rule_result> &results, object_store &store,
    cache_type &cache, const exclusion::exclusion_policy &exclusion,
    const matcher_mapper &dynamic_matchers, ddwaf::timer &deadline) const
{
    auto &apt_deadline = get_deadline(deadline);

    if (collections_.empty()) {
        auto final_verdict = verdict_type::none;
        for (std::size_t i = 0; i < rules_.size(); ++i) {
            const auto &rule = *rules_[i];
            auto &rule_cache = cache.rules[i];

            auto [verdict, outcome] =
                eval_rule(rule, store, rule_cache, exclusion, dynamic_matchers, apt_deadline);
            if (outcome.has_value()) {
                results.emplace_back(std::move(*outcome));
                DDWAF_DEBUG("Found event on rule {}", rule.get_id());
                final_verdict = verdict;
                if (final_verdict == verdict_type::block) {
                    break;
                }
            }
        }
        return final_verdict;
    }

    return eval_with_collections(results, store, cache, exclusion, dynamic_matchers, apt_deadline);
}
} // namespace ddwaf
