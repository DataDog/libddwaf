// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule.hpp>

#include <waf.hpp>

#include "clock.hpp"
#include <log.hpp>
#include <exception.hpp>
#include <memory>

namespace ddwaf
{

rule::rule(std::string &&id_, std::string &&name_,
  std::string &&type_, std::string &&category_,
  std::vector<std::shared_ptr<condition>> &&conditions_,
  std::vector<std::string> &&actions_):
  id(std::move(id_)), name(std::move(name_)),
  type(std::move(type_)), category(std::move(category_)), 
  conditions(std::move(conditions_)), actions(std::move(actions_))
{
    for (auto &cond : conditions) {
        const auto &cond_targets = cond->get_targets();
        targets.insert(cond_targets.begin(), cond_targets.end());
    }
}

bool rule::has_new_targets(const object_store &store) const
{
    for (const auto& target : targets)
    {
        if (store.is_new_target(target)) {
            return true;
        }
    }

    return false;
}

std::optional<event> rule::match(const object_store& store,
    const ddwaf::manifest &manifest, cache_type &cache,
    ddwaf::timer& deadline) const
{
    for (auto& cond : conditions) {
        bool run_on_new = false;
        auto cached_result = cache.conditions.find(cond);
        if (cached_result != cache.conditions.end()) {
            if (cached_result->second) {
                continue;
            }
            run_on_new = true;
        } else {
            auto [it, res] = cache.conditions.emplace(cond, false);
            cached_result = it;
        }

        auto opt_match = cond->match(store, manifest, run_on_new, deadline);
        if (!opt_match.has_value()) {
            cached_result->second = false;
            return std::nullopt;
        }
        cached_result->second = true;
        cache.event.matches.emplace_back(std::move(*opt_match));
    }

    cache.event.id = id;
    cache.event.name = name;
    cache.event.type =  type;
    cache.event.category = category;

    cache.event.actions.reserve(actions.size());
    for (const auto &action : actions) {
        cache.event.actions.push_back(action);
    }

    return {std::move(cache.event)};
}

}
