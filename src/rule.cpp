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

rule::rule(index_type index_, std::string &&id_, std::string &&name_,
  std::string &&type_, std::string &&category_,
  std::vector<std::shared_ptr<condition>> &&conditions_,
  std::vector<std::string> &&actions_):
  index(index_), id(std::move(id_)), name(std::move(name_)),
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
    const ddwaf::manifest &manifest, bool run_on_new,
    ddwaf::timer& deadline) const
{
    ddwaf::event event;

    for (auto& cond : conditions) {
        auto opt_match = cond->match(store, manifest, run_on_new, deadline);
        if (!opt_match.has_value()) {
            return std::nullopt;
        }
        event.matches.emplace_back(std::move(*opt_match));
    }

    event.id = id;
    event.name = name;
    event.type =  type;
    event.category = category;

    event.actions.reserve(actions.size());
    for (const auto &action : actions) {
        event.actions.push_back(action);
    }

    return {std::move(event)};
}

}
