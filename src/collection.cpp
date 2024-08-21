// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "clock.hpp"
#include "collection.hpp"
#include "context_allocator.hpp"
#include "event.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "rule.hpp"

namespace ddwaf {

std::optional<event> match_rule(rule *rule, const object_store &store,
    memory::unordered_map<ddwaf::rule *, rule::cache_type> &cache,
    const exclusion::context_policy &policy,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    const object_limits &limits, ddwaf::timer &deadline)
{
    const auto &id = rule->get_id();

    if (deadline.expired()) {
        DDWAF_INFO("Ran out of time while evaluating rule '{}'", id);
        throw timeout_exception();
    }

    if (!rule->is_enabled()) {
        DDWAF_DEBUG("Rule '{}' is disabled", id);
        return std::nullopt;
    }

    std::string_view action_override;
    auto exclusion = policy.find(rule);
    if (exclusion.mode == exclusion::filter_mode::bypass) {
        DDWAF_DEBUG("Bypassing rule '{}'", id);
        return std::nullopt;
    }

    if (exclusion.mode == exclusion::filter_mode::monitor) {
        DDWAF_DEBUG("Monitoring rule '{}'", id);
        action_override = "monitor";
    } else if (exclusion.mode == exclusion::filter_mode::custom) {
        action_override = exclusion.action_override;
        DDWAF_DEBUG("Evaluating rule '{}' with custom action '{}'", id, action_override);
    } else {
        DDWAF_DEBUG("Evaluating rule '{}'", id);
    }

    try {
        auto it = cache.find(rule);
        if (it == cache.end()) {
            auto [new_it, res] = cache.emplace(rule, rule::cache_type{});
            it = new_it;
        }

        rule::cache_type &rule_cache = it->second;
        std::optional<event> event;
        event =
            rule->match(store, rule_cache, exclusion.objects, dynamic_matchers, limits, deadline);

        if (event.has_value()) {
            event->action_override = action_override;
        }

        return event;
    } catch (const ddwaf::timeout_exception &) {
        DDWAF_INFO("Ran out of time while evaluating rule '{}'", id);
        throw;
    }

    return std::nullopt;
}

template <typename Derived>
void base_collection<Derived>::match(std::vector<event> &events, object_store &store,
    collection_cache &cache, const exclusion::context_policy &exclusion,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    const object_limits &limits, ddwaf::timer &deadline) const
{
    if (cache.result >= Derived::type()) {
        // If the result was cached but ephemeral, clear it. Note that this is
        // just a workaround taking advantage of the order of evaluation of
        // collections. Collections might be removed in the future altogether.
        if (cache.result == Derived::type() && cache.ephemeral) {
            cache.result = collection_type::none;
            cache.ephemeral = false;
        } else {
            return;
        }
    }

    for (auto *rule : rules_) {
        auto event = match_rule(
            rule, store, cache.rule_cache, exclusion, dynamic_matchers, limits, deadline);
        if (event.has_value()) {
            cache.result = Derived::type();
            cache.ephemeral = event->ephemeral;

            events.emplace_back(std::move(*event));
            DDWAF_DEBUG("Found event on rule {}", rule->get_id());
            break;
        }
    }
}

template class base_collection<collection>;
template class base_collection<priority_collection>;

} // namespace ddwaf
