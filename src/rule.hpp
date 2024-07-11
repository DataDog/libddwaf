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

#include "clock.hpp"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "iterator.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"

namespace ddwaf {

class rule {
public:
    enum class source_type : uint8_t { base = 1, user = 2 };

    using cache_type = expression::cache_type;

    rule(std::string id, std::string name, std::unordered_map<std::string, std::string> tags,
        std::shared_ptr<expression> expr, std::vector<std::string> actions = {},
        bool enabled = true, source_type source = source_type::base)
        : enabled_(enabled), source_(source), id_(std::move(id)), name_(std::move(name)),
          tags_(std::move(tags)), expr_(std::move(expr)), actions_(std::move(actions))
    {
        if (!expr_) {
            throw std::invalid_argument("rule constructed with null expression");
        }
    }

    rule(const rule &) = delete;
    rule &operator=(const rule &) = delete;

    rule(rule &&rhs) noexcept = default;
    rule &operator=(rule &&rhs) = default;

    virtual ~rule() = default;

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

    [[nodiscard]] bool is_enabled() const { return enabled_; }
    void toggle(bool value) { enabled_ = value; }

    source_type get_source() const { return source_; }
    const std::string &get_id() const { return id_; }
    const std::string &get_name() const { return name_; }

    std::string_view get_tag(const std::string &tag) const
    {
        auto it = tags_.find(tag);
        return it == tags_.end() ? std::string_view() : it->second;
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
    source_type source_;
    std::string id_;
    std::string name_;
    std::unordered_map<std::string, std::string> tags_;
    std::unordered_map<std::string, std::string> ancillary_tags_;
    std::shared_ptr<expression> expr_;
    std::vector<std::string> actions_;
};

} // namespace ddwaf
