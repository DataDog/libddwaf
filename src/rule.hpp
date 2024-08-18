// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "clock.hpp"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
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

    std::string_view get_tag_or(const std::string &tag, std::string_view or_value) const
    {
        auto it = tags_.find(tag);
        return it == tags_.end() ? or_value : it->second;
    }

    const std::unordered_map<std::string, std::string> &get_tags() const { return tags_; }
    const std::unordered_map<std::string, std::string> &get_ancillary_tags() const
    {
        return ancillary_tags_;
    }

    void set_ancillary_tag(const std::string &key, const std::string &value)
    {
        // Ancillary tags aren't allowed to overlap with standard tags
        if (!tags_.contains(key)) {
            ancillary_tags_[key] = value;
        }
    }

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
    std::unordered_map<std::string, std::string> ancillary_tags_;
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

        return {ddwaf::event{this, expression::get_matches(cache), res.ephemeral, {}}};
    }

    source_type get_source() const { return source_; }

protected:
    source_type source_;
};

class base_threshold_rule : public base_rule {
public:
    using cache_type = expression::cache_type;

    base_threshold_rule(std::string id, std::string name,
        std::unordered_map<std::string, std::string> tags, std::shared_ptr<expression> expr,
        std::vector<std::string> actions = {}, bool enabled = true)
        : base_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled)
    {}
    ~base_threshold_rule() override = default;
    base_threshold_rule(const base_threshold_rule &) = delete;
    base_threshold_rule &operator=(const base_threshold_rule &) = delete;
    base_threshold_rule(base_threshold_rule &&rhs) noexcept = default;
    base_threshold_rule &operator=(base_threshold_rule &&rhs) noexcept = default;

    virtual std::optional<event> eval(const object_store &store, cache_type &cache,
        monotonic_clock::time_point now, ddwaf::timer &deadline) = 0;
};

class threshold_rule : public base_threshold_rule {
public:
    struct evaluation_criteria {
        std::size_t threshold;
        std::chrono::milliseconds period{};
    };

    threshold_rule(std::string id, std::string name,
        std::unordered_map<std::string, std::string> tags, std::shared_ptr<expression> expr,
        evaluation_criteria criteria, std::vector<std::string> actions = {}, bool enabled = true)
        : base_threshold_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          criteria_(criteria), counter_(criteria_.period, criteria_.threshold * 2),
          threshold_str_(to_string<std::string>(criteria_.threshold))
    {}

    ~threshold_rule() override = default;
    threshold_rule(const threshold_rule &) = delete;
    threshold_rule &operator=(const threshold_rule &) = delete;
    threshold_rule(threshold_rule &&rhs) noexcept = delete;
    threshold_rule &operator=(threshold_rule &&rhs) noexcept = delete;

    std::optional<event> eval(const object_store &store, cache_type &cache,
        monotonic_clock::time_point now, ddwaf::timer &deadline) override;

protected:
    evaluation_criteria criteria_;
    timed_counter_ts_ms counter_;
    std::string threshold_str_;
};

class indexed_threshold_rule : public base_threshold_rule {
public:
    struct evaluation_criteria {
        std::string name;
        target_index target;
        std::size_t threshold;
        std::chrono::milliseconds period;
    };

    indexed_threshold_rule(std::string id, std::string name,
        std::unordered_map<std::string, std::string> tags, std::shared_ptr<expression> expr,
        evaluation_criteria criteria, std::vector<std::string> actions = {}, bool enabled = true)
        : base_threshold_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          criteria_(std::move(criteria)), counter_(criteria_.period, 128, criteria_.threshold * 2),
          threshold_str_(to_string<std::string>(criteria_.threshold))
    {}

    ~indexed_threshold_rule() override = default;
    indexed_threshold_rule(const indexed_threshold_rule &) = delete;
    indexed_threshold_rule &operator=(const indexed_threshold_rule &) = delete;
    indexed_threshold_rule(indexed_threshold_rule &&rhs) noexcept = delete;
    indexed_threshold_rule &operator=(indexed_threshold_rule &&rhs) noexcept = delete;

    std::optional<event> eval(const object_store &store, cache_type &cache,
        monotonic_clock::time_point now, ddwaf::timer &deadline) override;

protected:
    evaluation_criteria criteria_;
    indexed_timed_counter_ts_ms counter_;
    std::string threshold_str_;
};

} // namespace ddwaf
