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
#include "module_category.hpp"
#include "object_store.hpp"

namespace ddwaf {

// A core rule constitutes the most important type of entity within the
// evaluation process. These rules are "request-bound", i.e. they are used to
// specifically analyse request data, as opposed to other types of rules such
// as threshold rules which analyse data across requests.
class core_rule {
public:
    enum class source_type : uint8_t { base = 1, user = 2 };
    enum class verdict_type : uint8_t { none = 0, monitor = 1, block = 2 };

    using cache_type = expression::cache_type;

    core_rule(std::string id, std::string name, std::unordered_map<std::string, std::string> tags,
        std::shared_ptr<expression> expr, std::vector<std::string> actions = {},
        bool enabled = true, source_type source = source_type::base,
        verdict_type verdict = verdict_type::monitor)
        : enabled_(enabled), source_(source), verdict_(verdict), id_(std::move(id)),
          name_(std::move(name)), tags_(std::move(tags)), actions_(std::move(actions)),
          expr_(std::move(expr))
    {
        if (!expr_) {
            throw std::invalid_argument("rule constructed with null expression");
        }

        // If the tag is not present, the default is `waf`
        mod_ = string_to_rule_module_category(get_tag_or("module", "waf"));
        // Type is guaranteed to be present
        type_ = get_tag("type");
    }

    core_rule(const core_rule &) = delete;
    core_rule &operator=(const core_rule &) = delete;

    core_rule(core_rule &&rhs) noexcept = default;
    core_rule &operator=(core_rule &&rhs) = default;

    virtual ~core_rule() = default;

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

    [[nodiscard]] source_type get_source() const { return source_; }

    std::string_view get_id() const { return id_; }
    std::string_view get_name() const { return name_; }
    std::string_view get_type() const { return type_; }
    rule_module_category get_module() const { return mod_; }

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

    [[nodiscard]] bool has_actions() const { return !actions_.empty(); }
    const std::vector<std::string> &get_actions() const { return actions_; }

    verdict_type get_verdict() const { return verdict_; }
    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        return expr_->get_addresses(addresses);
    }

protected:
    // General metadata
    bool enabled_{true};
    source_type source_;
    verdict_type verdict_{verdict_type::monitor};
    std::string id_;
    std::string name_;
    std::unordered_map<std::string, std::string> tags_;
    std::vector<std::string> actions_;

    // Frequently accessed tags
    std::string_view type_;
    rule_module_category mod_;

    // Evaluable expression encompassing all the rule's conditions
    std::shared_ptr<expression> expr_;
};

} // namespace ddwaf
