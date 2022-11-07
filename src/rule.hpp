// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <PWTransformer.h>
#include <clock.hpp>
#include <condition.hpp>
#include <event.hpp>
#include <iterator.hpp>
#include <manifest.hpp>
#include <object_store.hpp>
#include <rule_processor/base.hpp>

namespace ddwaf
{

class rule
{
public:
    struct cache_type {
        bool result{false};
        std::unordered_map<std::shared_ptr<condition>, bool> conditions;
        ddwaf::event event;
    };

    // TODO: make fields protected, add getters, follow conventions, add cache
    //       move condition matching from context.

    rule(std::string &&id_, std::string &&name_,
      std::string &&type_, std::string &&category_,
      std::vector<std::shared_ptr<condition>> &&conditions_,
      std::vector<std::string> &&actions_ = {});

    rule(const rule&) = delete;
    rule& operator=(const rule&) = delete;

    // Atomics aren't movable so the default move constructor and move
    // assignment operator can't be used. With this constructor and operator
    // any relevant atomic member does not behave as such.
    rule(rule &&rhs) noexcept :
        enabled(rhs.enabled.load(std::memory_order_relaxed)),
        id(std::move(rhs.id)),
        name(std::move(rhs.name)),
        type(std::move(rhs.type)),
        category(std::move(rhs.category)),
        conditions(std::move(rhs.conditions)),
        targets(std::move(rhs.targets)),
        actions(std::move(rhs.actions)) {}

    rule& operator=(rule &&rhs)  noexcept {
        enabled = rhs.enabled.load(std::memory_order_relaxed);
        id = std::move(rhs.id);
        name = std::move(rhs.name);
        type = std::move(rhs.type);
        category = std::move(rhs.category);
        conditions = std::move(rhs.conditions);
        targets = std::move(rhs.targets);
        actions = std::move(rhs.actions);

        return *this;
    }

    ~rule() = default;

    std::optional<event> match(const object_store& store,
        const ddwaf::manifest &manifest, cache_type &cache,
        ddwaf::timer& deadline) const;

    bool is_enabled() const { return enabled.load(std::memory_order_relaxed); }
    void toggle(bool value) { enabled.store(value, std::memory_order_relaxed); }

    std::atomic<bool> enabled{true};
    std::string id;
    std::string name;
    std::string type;
    std::string category;
    std::vector<std::shared_ptr<condition>> conditions;
    std::unordered_set<ddwaf::manifest::target_type> targets;
    std::vector<std::string> actions;
};

}
