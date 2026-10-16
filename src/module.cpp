// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <module.hpp>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "cache_array.hpp"
#include "clock.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "rule.hpp"

namespace ddwaf {

namespace {
using verdict_type = rule_module::verdict_type;

constexpr std::size_t pending_word_bits = rule_module_cache::pending_word_bits;

// Returns the position of the first pending rule within [pos, end), or end if none
std::size_t next_pending(std::span<const uint64_t> pending, std::size_t pos, std::size_t end)
{
    while (pos < end) {
        const uint64_t word = pending[pos / pending_word_bits] >> (pos % pending_word_bits);
        if (word != 0) {
            return std::min(pos + std::countr_zero(word), end);
        }
        pos = ((pos / pending_word_bits) + 1) * pending_word_bits;
    }
    return end;
}

void check_deadline(ddwaf::timer &deadline)
{
    if (deadline.expired()) {
        DDWAF_INFO("Ran out of time while evaluating rules");
        throw timeout_exception();
    }
}

void clear_pending(std::span<uint64_t> pending, std::size_t pos)
{
    pending[pos / pending_word_bits] &= ~(uint64_t{1} << (pos % pending_word_bits));
}

std::pair<verdict_type, std::optional<rule_result>> eval_rule(const core_rule &rule,
    const object_store &store, cache_array<core_rule::cache_type> &caches, std::size_t index,
    const exclusion_policy &policy, const matcher_mapper &dynamic_matchers, ddwaf::timer &deadline)
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
    if (exclusion.mode == filter_mode::bypass) {
        DDWAF_DEBUG("Bypassing rule '{}'", id);
        return {verdict_type::none, std::nullopt};
    }

    rule_verdict verdict_override = rule_verdict::none;
    if (exclusion.mode == filter_mode::monitor) {
        action_override = "monitor";
        verdict_override = verdict_type::monitor;
        DDWAF_DEBUG("Monitoring rule '{}'", id);
    } else if (exclusion.mode == filter_mode::custom) {
        action_override = exclusion.action_override;
        verdict_override = verdict_type::block;
        DDWAF_DEBUG("Evaluating rule '{}' with custom action '{}'", id, action_override);
    } else {
        DDWAF_DEBUG("Evaluating rule '{}'", id);
    }

    try {
        // A rule which has already matched doesn't match again, as checked by
        // core_rule::match, which can be determined without copying a cache
        // inherited from a context.
        auto [verdict, outcome] = expression::get_result(std::as_const(caches).get(index))
                                      ? std::pair{verdict_type::none, std::optional<rule_result>{}}
                                      : rule.match(store, caches.get_writable(index),
                                            exclusion.objects, dynamic_matchers, deadline);

        if (outcome.has_value()) {
            outcome->action_override = action_override;
        }

        if (verdict_override != rule_verdict::none) {
            verdict = verdict_override;
        }

        return {verdict, std::move(outcome)};
    } catch (const ddwaf::timeout_exception &) {
        DDWAF_INFO("Ran out of time while evaluating rule '{}'", id);
        throw;
    }

    return {verdict_type::none, std::nullopt};
}

} // namespace

verdict_type rule_module::eval_with_collections(std::vector<rule_result> &results,
    object_store &store, cache_type &cache, const exclusion_policy &exclusion,
    const matcher_mapper &dynamic_matchers, ddwaf::timer &deadline) const
{
    verdict_type final_verdict = verdict_type::none;
    bool deadline_checked = false;
    for (const auto &collection : collections_) {
        auto &collection_cache = cache.collections[collection.slot];
        if (collection_cache.type >= collection.type) {
            continue;
        }

        // See rule_module::eval
        if (!deadline_checked && collection.begin < collection.end) {
            deadline_checked = true;
            check_deadline(deadline);
        }

        auto i = next_pending(cache.pending, collection.begin, collection.end);
        if (i == collection.end) {
            // None of the rules in the collection needs to be evaluated
            continue;
        }

        DDWAF_DEBUG("Evaluating collection: {}", collection.name);

        for (; i < collection.end; i = next_pending(cache.pending, i + 1, collection.end)) {
            const auto &rule = *rules_[i];
            auto [verdict, outcome] =
                eval_rule(rule, store, cache.rules, i, exclusion, dynamic_matchers, deadline);
            clear_pending(cache.pending, i);
            if (outcome.has_value()) {
                collection_cache.type = verdict;

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
    cache_type &cache, const exclusion_policy &exclusion, const matcher_mapper &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    // Non-expiring modules use their own timer, which doesn't read the clock
    // and, unlike a shared one, isn't written to by concurrent evaluations.
    auto no_deadline = ddwaf::timer::unbounded();
    auto &apt_deadline = may_expire() ? deadline : no_deadline;

    if (collections_.empty()) {
        // Rules whose targets haven't been updated aren't evaluated, but the
        // deadline is still checked as if they were, so that an expired
        // deadline interrupts the evaluation of the module (and so of the
        // batch) even when it has no pending rules.
        if (!rules_.empty()) {
            check_deadline(apt_deadline);
        }

        auto final_verdict = verdict_type::none;
        for (auto i = next_pending(cache.pending, 0, rules_.size()); i < rules_.size();
             i = next_pending(cache.pending, i + 1, rules_.size())) {
            const auto &rule = *rules_[i];
            auto [verdict, outcome] =
                eval_rule(rule, store, cache.rules, i, exclusion, dynamic_matchers, apt_deadline);
            clear_pending(cache.pending, i);
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
