// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <memory>
#include <module.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "clock.hpp"
#include "event.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "rule.hpp"

namespace ddwaf {

namespace {
std::optional<event> eval_rule(const core_rule &rule, const object_store &store,
    core_rule::cache_type &cache, const exclusion::context_policy &policy,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline)
{
    const auto &id = rule.get_id();

    if (deadline.expired()) {
        DDWAF_INFO("Ran out of time while evaluating rule '{}'", id);
        throw timeout_exception();
    }

    if (!rule.is_enabled()) {
        DDWAF_DEBUG("Rule '{}' is disabled", id);
        return std::nullopt;
    }

    std::string_view action_override;
    auto exclusion = policy.find(&rule);
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
        std::optional<event> event;
        event = rule.match(store, cache, exclusion.objects, dynamic_matchers, deadline);

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

} // namespace

void rule_module::eval_with_collections(std::vector<event> &events, object_store &store,
    cache_type &cache, const exclusion::context_policy &exclusion,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    for (const auto &collection : collections_) {
        DDWAF_DEBUG("Evaluating collection: {}", collection.name);
        auto &collection_cache = cache.collections[collection.name];
        if (collection_cache.type >= collection.type) {
            // If the result was cached but ephemeral, clear it. Note that this is
            // just a workaround taking advantage of the order of evaluation of
            // collections. Collections might be removed in the future altogether.
            if (collection_cache.type == collection.type && collection_cache.ephemeral) {
                collection_cache.type = core_rule::verdict_type::none;
                collection_cache.ephemeral = false;
            } else {
                continue;
            }
        }

        for (std::size_t i = collection.begin; i < collection.end; ++i) {
            auto &rule = *rules_[i];
            auto event =
                eval_rule(rule, store, cache.rules[i], exclusion, dynamic_matchers, deadline);
            if (event.has_value()) {
                collection_cache.type = rule.get_verdict();
                collection_cache.ephemeral = event->ephemeral;

                events.emplace_back(std::move(*event));
                DDWAF_DEBUG("Found event on rule {}", rule.get_id());
                break;
            }
        }
    }
}

void rule_module::eval(std::vector<event> &events, object_store &store, cache_type &cache,
    const exclusion::context_policy &exclusion,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    if (collections_.empty()) {
        for (std::size_t i = 0; i < rules_.size(); ++i) {
            const auto &rule = *rules_[i];
            auto &rule_cache = cache.rules[i];

            auto event = eval_rule(rule, store, rule_cache, exclusion, dynamic_matchers, deadline);
            if (event.has_value()) {
                events.emplace_back(std::move(*event));
                DDWAF_DEBUG("Found event on rule {}", rule.get_id());
                break;
            }
        }
    } else {
        eval_with_collections(events, store, cache, exclusion, dynamic_matchers, deadline);
    }
}
} // namespace ddwaf
