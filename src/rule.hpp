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

#include <bazel-cel-cpp-wrapper/main/cel_wrapper.hpp>

namespace ddwaf {

class rule_base {
public:
    using ptr = std::shared_ptr<rule_base>;
    struct cache_type {
        bool result{false};
        std::unordered_map<condition::ptr, bool> conditions;
        ddwaf::event event;
    };

    rule_base(std::string &&id_, std::string &&name_, std::string &&type_,
        std::string &&category_, std::vector<std::string> &&actions_ = {});
    rule_base(const rule_base &) = delete;
    rule_base &operator=(const rule_base &) = delete;

    rule_base(rule_base &&rhs) noexcept
        : enabled(rhs.enabled.load(std::memory_order_relaxed)), id(std::move(rhs.id)),
          name(std::move(rhs.name)), type(std::move(rhs.type)), category(std::move(rhs.category)),
          actions(std::move(rhs.actions)) {}

    rule_base &operator=(rule_base &&rhs) noexcept
    {
        enabled = rhs.enabled.load(std::memory_order_relaxed);
        id = std::move(rhs.id);
        name = std::move(rhs.name);
        type = std::move(rhs.type);
        category = std::move(rhs.category);
        actions = std::move(rhs.actions);
        return *this;
    }


    virtual ~rule_base() = default;

    virtual std::optional<event> match(
        const object_store &store, const ddwaf::manifest &manifest,
        cache_type &cache, ddwaf::timer &deadline) const = 0;

    [[nodiscard]] std::string_view get_id() const { return id; }
    [[nodiscard]] std::string_view get_name() const { return name; }
    [[nodiscard]] std::string_view get_type() const { return type; }
    [[nodiscard]] std::string_view get_category() const { return category; }

    [[nodiscard]] bool is_enabled() const { return enabled.load(std::memory_order_relaxed); }
    void toggle(bool value) { enabled.store(value, std::memory_order_relaxed); }

    std::atomic<bool> enabled{true};
    std::string id;
    std::string name;
    std::string type;
    std::string category;
    std::vector<std::string> actions;
};

class rule : public rule_base {
public:
    // TODO: make fields protected, add getters, follow conventions, add cache
    //       move condition matching from context.

    rule(std::string &&id_, std::string &&name_, std::string &&type_, std::string &&category_,
        std::vector<condition::ptr> &&conditions_, std::vector<std::string> &&actions_ = {});

    rule(const rule &) = delete;
    rule &operator=(const rule &) = delete;

    // Atomics aren't movable so the default move constructor and move
    // assignment operator can't be used. With this constructor and operator
    // any relevant atomic member does not behave as such.
    rule(rule &&rhs) noexcept
        : rule_base(std::move(rhs)), conditions(std::move(rhs.conditions)) {}

    rule &operator=(rule &&rhs) noexcept
    {
        rule_base::operator=(std::move(rhs));
        conditions = std::move(rhs.conditions);
        targets = std::move(rhs.targets);
        return *this;
    }

    ~rule() override = default;

    std::optional<event> match(const object_store &store, const ddwaf::manifest &manifest,
        cache_type &cache, ddwaf::timer &deadline) const override;

protected:
    std::vector<condition::ptr> conditions;
    std::unordered_set<ddwaf::manifest::target_type> targets;
};

class expression_rule : public rule_base {
public:
    expression_rule(std::string &&id_, std::string &&name_, std::string &&type_,
        std::string &&category_, const std::string &expression_,
        std::vector<ddwaf::manifest::target_type> &&targets_,
        std::vector<std::string> &&actions_ = {})
    : rule_base(std::move(id_), std::move(name_), std::move(type_),
      std::move(category_), std::move(actions_)),
      expr_(expression_rule::builder.build(expression_)),
      targets(std::move(targets_)) {}


    expression_rule(const expression_rule &) = delete;
    expression_rule &operator=(const expression_rule &) = delete;

    expression_rule(expression_rule &&rhs) noexcept
        : rule_base(std::move(rhs)), expr_(std::move(rhs.expr_)) {}

    expression_rule &operator=(expression_rule &&rhs) noexcept
    {
        rule_base::operator=(std::move(rhs));
        expr_ = std::move(rhs.expr_);
        targets = std::move(rhs.targets);
        return *this;
    }

    ~expression_rule() override = default;

    std::optional<event> match(const object_store &store, const ddwaf::manifest &manifest,
        cache_type &cache, ddwaf::timer &deadline) const override;

protected:
    static datadog::waf::expression_builder builder;
    std::weak_ptr<datadog::waf::expression> expr_;
    std::vector<ddwaf::manifest::target_type> targets;
};

} // namespace ddwaf
