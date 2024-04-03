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
#include <utility>
#include <variant>
#include <vector>

#include "clock.hpp"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "iterator.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "timed_counter.hpp"

namespace ddwaf {

class base_rule {
public:
    base_rule(std::string id, std::string name, std::unordered_map<std::string, std::string> tags,
        std::shared_ptr<expression> expr, std::vector<std::string> actions = {},
        bool enabled = true)
        : enabled_(enabled), id_(std::move(id)), name_(std::move(name)), tags_(std::move(tags)),
          expr_(std::move(expr)), actions_(std::move(actions))
    {
        if (!expr_) {
            throw std::invalid_argument("rule constructed with null expression");
        }
    }

    base_rule(const base_rule &) = delete;
    base_rule &operator=(const base_rule &) = delete;

    base_rule(base_rule &&rhs) noexcept = default;
    base_rule &operator=(base_rule &&rhs) noexcept = default;

    virtual ~base_rule() = default;

    [[nodiscard]] bool is_enabled() const { return enabled_; }
    void toggle(bool value) { enabled_ = value; }

    const std::string &get_id() const { return id_; }
    const std::string &get_name() const { return name_; }

    std::string_view get_tag(const std::string &tag) const
    {
        auto it = tags_.find(tag);
        return it == tags_.end() ? std::string_view() : it->second;
    }

    const std::unordered_map<std::string, std::string> &get_tags() const { return tags_; }

    const std::vector<std::string> &get_actions() const { return actions_; }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        return expr_->get_addresses(addresses);
    }

    void set_actions(std::vector<std::string> new_actions) { actions_ = std::move(new_actions); }

protected:
    bool enabled_{true};
    std::string id_;
    std::string name_;
    std::unordered_map<std::string, std::string> tags_;
    std::shared_ptr<expression> expr_;
    std::vector<std::string> actions_;
};

class rule : public base_rule {
public:
    enum class source_type : uint8_t { base = 1, user = 2 };

    using cache_type = expression::cache_type;

    rule(std::string id, std::string name, std::unordered_map<std::string, std::string> tags,
        std::shared_ptr<expression> expr, std::vector<std::string> actions = {},
        bool enabled = true, source_type source = source_type::base)
        : base_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          source_(source)
    {}

    rule(const rule &) = delete;
    rule &operator=(const rule &) = delete;

    rule(rule &&rhs) noexcept = default;
    rule &operator=(rule &&rhs) noexcept = default;

    ~rule() override = default;

    virtual std::optional<event> match(const object_store &store, cache_type &cache,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        ddwaf::timer &deadline) const
    {
        if (expression::get_result(cache)) {
            // An event was already produced, so we skip the rule
            return std::nullopt;
        }

        auto res = expr_->eval(cache, store, objects_excluded, dynamic_matchers, deadline);
        if (!res.outcome) {
            return std::nullopt;
        }

        return {ddwaf::event{this, expression::get_matches(cache), res.ephemeral}};
    }

    source_type get_source() const { return source_; }

protected:
    source_type source_;
};

class threshold_rule : public base_rule {
public:
    struct evaluation_criteria {
        std::size_t threshold;
        std::chrono::milliseconds period;
    };

    using local_cache_type = expression::cache_type;
    using global_cache_type = timed_counter_ms;

    threshold_rule(std::string id, std::string name,
        std::unordered_map<std::string, std::string> tags, std::shared_ptr<expression> expr,
        evaluation_criteria criteria, std::vector<std::string> actions = {}, bool enabled = true)
        : base_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          criteria_(criteria)
    {}

    ~threshold_rule() override = default;
    threshold_rule(const threshold_rule &) = delete;
    threshold_rule &operator=(const threshold_rule &) = delete;
    threshold_rule(threshold_rule &&rhs) noexcept = default;
    threshold_rule &operator=(threshold_rule &&rhs) noexcept = default;

    std::optional<event> eval(const object_store &store, global_cache_type &gcache,
        local_cache_type &lcache, ddwaf::timer &deadline) const;

    global_cache_type init_global_cache() const
    {
        auto max_window_size = criteria_.threshold * 2;
        return timed_counter_ms{criteria_.period, max_window_size};
    }

protected:
    evaluation_criteria criteria_;
};

class indexed_threshold_rule : public base_rule {
public:
    struct evaluation_criteria {
        std::string name;
        target_index target;
        std::size_t threshold;
        std::chrono::milliseconds period;
    };

    using local_cache_type = expression::cache_type;
    using global_cache_type = indexed_timed_counter_ms;

    indexed_threshold_rule(std::string id, std::string name,
        std::unordered_map<std::string, std::string> tags, std::shared_ptr<expression> expr,
        evaluation_criteria criteria, std::vector<std::string> actions = {}, bool enabled = true)
        : base_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          criteria_(std::move(criteria))
    {}

    ~indexed_threshold_rule() override = default;
    indexed_threshold_rule(const indexed_threshold_rule &) = delete;
    indexed_threshold_rule &operator=(const indexed_threshold_rule &) = delete;
    indexed_threshold_rule(indexed_threshold_rule &&rhs) noexcept = default;
    indexed_threshold_rule &operator=(indexed_threshold_rule &&rhs) noexcept = default;

    std::optional<event> eval(const object_store &store, global_cache_type &gcache,
        local_cache_type &lcache, ddwaf::timer &deadline) const;

    global_cache_type init_global_cache() const
    {
        auto max_window_size = criteria_.threshold * 2;
        return indexed_timed_counter_ms{criteria_.period, 128, max_window_size};
    }

protected:
    evaluation_criteria criteria_;
};

} // namespace ddwaf
