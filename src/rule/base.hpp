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
#include "sliding_window_counter.hpp"

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

} // namespace ddwaf
