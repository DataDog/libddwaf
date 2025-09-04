// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "clock.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "matcher/base.hpp"
#include "module_category.hpp"
#include "object_store.hpp"

namespace ddwaf {

/**
 * Flags that control rule behavior
 */
enum class rule_flags : uint8_t {
    none = 0,
    generate_event = 1 << 0, // Generate an event when rule matches
    keep_outcome = 1 << 1    // Prevent the outcome from being dropped on sampling
};

// Enable bitwise operations on rule_flags
constexpr ddwaf::rule_flags operator|(ddwaf::rule_flags a, ddwaf::rule_flags b) noexcept
{
    return static_cast<ddwaf::rule_flags>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}

constexpr ddwaf::rule_flags operator&(ddwaf::rule_flags a, ddwaf::rule_flags b) noexcept
{
    return static_cast<ddwaf::rule_flags>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
}

constexpr bool operator==(ddwaf::rule_flags a, ddwaf::rule_flags b) noexcept
{
    return static_cast<uint8_t>(a) == static_cast<uint8_t>(b);
}

constexpr bool operator!=(ddwaf::rule_flags a, ddwaf::rule_flags b) noexcept
{
    return static_cast<uint8_t>(a) != static_cast<uint8_t>(b);
}

constexpr bool contains(rule_flags set, rule_flags opt) { return (set & opt) != rule_flags::none; }

enum class rule_verdict : uint8_t { none = 0, monitor = 1, block = 2 };
enum class rule_source : uint8_t { base = 1, user = 2 };

struct rule_attribute {
    struct input_target {
        std::string name;
        target_index index;
        std::vector<std::string> key_path;
    };
    std::variant<input_target, std::string, uint64_t, int64_t, double, bool> value_or_target;
    std::string key;
};

struct rule_event {
    struct {
        std::string_view id;
        std::string_view name;
        std::reference_wrapper<const std::unordered_map<std::string, std::string>> tags;
    } rule;
    std::vector<condition_match> matches;
};

struct rule_result {
    bool keep{false};
    evaluation_scope scope;

    std::optional<rule_event> event{std::nullopt};

    std::string_view action_override;
    std::reference_wrapper<const std::vector<std::string>> actions;

    std::reference_wrapper<const std::vector<rule_attribute>> attributes;
};

struct rule_cache {
    bool attributes_generated{false};
    expression::cache_type expr_cache;
};

// A core rule constitutes the most important type of entity within the
// evaluation process. These rules are "request-bound", i.e. they are used to
// specifically analyse request data, as opposed to other types of rules such
// as threshold rules which analyse data across requests.
class core_rule {
public:
    using source_type = rule_source;
    using verdict_type = rule_verdict;

    using cache_type = rule_cache;

    core_rule(std::string id,                              // Required: Unique identifier
        std::string name,                                  // Required: Human-readable name
        std::unordered_map<std::string, std::string> tags, // Required: Rule metadata
        std::shared_ptr<expression> expr,                  // Required: Rule expression
        std::vector<std::string> actions = {},             // Optional: Rule actions, default: none
        std::vector<rule_attribute> attributes = {},       // Optional: Attributes, default: none
        source_type source = source_type::base,            // Optional: Rule source, default: base
        verdict_type verdict = verdict_type::monitor, // Optional: Rule verdict: default: monitor
        bool enabled = true,                          // Optional: Enabled by default
        rule_flags flags = rule_flags::generate_event |
                           rule_flags::keep_outcome // Optional: Default flags
        )
        : enabled_(enabled), flags_(flags), source_(source), verdict_(verdict), id_(std::move(id)),
          name_(std::move(name)), tags_(std::move(tags)), actions_(std::move(actions)),
          attributes_(std::move(attributes)), expr_(std::move(expr))
    {
        if (!expr_) {
            throw std::invalid_argument("rule constructed with null expression");
        }

        // If the tag is not present, the default is `waf`
        auto it = tags_.find("module");
        if (it != tags_.end()) {
            mod_ = string_to_rule_module_category(it->second);
        }

        // Type is guaranteed to be present
        type_ = tags_["type"];
    }

    core_rule(const core_rule &) = delete;
    core_rule &operator=(const core_rule &) = delete;

    core_rule(core_rule &&rhs) noexcept = default;
    core_rule &operator=(core_rule &&rhs) = default;

    ~core_rule() = default;

    std::pair<verdict_type, std::optional<rule_result>> match(const object_store &store,
        cache_type &cache, const exclusion::object_set_ref &objects_excluded,
        const matcher_mapper &dynamic_matchers, ddwaf::timer &deadline) const;

    [[nodiscard]] bool is_enabled() const { return enabled_; }

    [[nodiscard]] std::string_view get_id() const { return id_; }
    [[nodiscard]] std::string_view get_name() const { return name_; }
    [[nodiscard]] std::string_view get_type() const { return type_; }
    [[nodiscard]] rule_module_category get_module() const { return mod_; }
    [[nodiscard]] verdict_type get_verdict() const { return verdict_; }

    [[nodiscard]] source_type get_source() const { return source_; }

    [[nodiscard]] const std::unordered_map<std::string, std::string> &get_tags() const
    {
        return tags_;
    }
    [[nodiscard]] const std::vector<std::string> &get_actions() const { return actions_; }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        expr_->get_addresses(addresses);
    }

    static void invalidate_subcontext_cache(cache_type &cache)
    {
        expression::invalidate_subcontext_cache(cache.expr_cache);
    }

protected:
    // General metadata
    bool enabled_{true};
    rule_flags flags_{rule_flags::generate_event | rule_flags::keep_outcome};
    source_type source_;
    verdict_type verdict_{verdict_type::monitor};
    std::string id_;
    std::string name_;
    std::unordered_map<std::string, std::string> tags_;
    std::vector<std::string> actions_;
    std::vector<rule_attribute> attributes_;

    // Frequently accessed tags
    std::string_view type_;
    rule_module_category mod_{rule_module_category::waf};

    // Evaluable expression encompassing all the rule's conditions
    std::shared_ptr<expression> expr_;
};

} // namespace ddwaf
