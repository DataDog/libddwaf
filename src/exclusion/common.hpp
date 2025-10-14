// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <unordered_set>

#include "object.hpp"
#include "utils.hpp"

namespace ddwaf {

class core_rule;

enum class filter_mode : uint8_t { none = 0, custom = 1, monitor = 2, bypass = 3 };

using object_set = std::unordered_set<object_cache_key>;

struct object_set_ref {
    optional_ref<const object_set> objects;

    object_set_ref() = default;

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    object_set_ref(std::nullopt_t /*unused*/) {}

    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    object_set_ref(const object_set &original) : objects(original) {}

    [[nodiscard]] bool empty() const { return !objects.has_value() || objects->get().empty(); }

    [[nodiscard]] std::size_t size() const
    {
        return objects.has_value() ? objects->get().size() : 0;
    }

    [[nodiscard]] bool contains(object_view obj) const
    {
        return objects.has_value() && objects->get().contains(obj);
    }
};

struct rule_policy {
    filter_mode mode{filter_mode::none};
    std::string_view action_override;
    std::unordered_set<object_cache_key> objects;
};

struct rule_policy_ref {
    filter_mode mode{filter_mode::none};
    std::string_view action_override;
    object_set_ref objects;
};

struct exclusion_policy {
    std::unordered_map<const core_rule *, rule_policy> per_rule;

    [[nodiscard]] bool empty() const { return per_rule.empty(); }

    [[nodiscard]] std::size_t size() const { return per_rule.size(); }

    bool contains(const core_rule *key) const { return per_rule.contains(key); }

    rule_policy_ref find(const core_rule *key) const
    {
        auto it = per_rule.find(key);
        if (it == per_rule.end()) {
            return {.mode = filter_mode::none, .action_override = {}, .objects = std::nullopt};
        }

        const auto &policy = it->second;
        return {.mode = policy.mode,
            .action_override = policy.action_override,
            .objects = policy.objects};
    }

    void add_rule_exclusion(const core_rule *rule, filter_mode mode, std::string_view action)
    {
        auto &policy = per_rule[rule];
        // Bypass has precedence over monitor
        if (policy.mode < mode) {
            policy.mode = mode;
            policy.action_override = action;
        }
    }

    void add_input_exclusion(const core_rule *rule, const object_set &objects)
    {
        auto &rule_policy = per_rule[rule];
        if (rule_policy.mode == filter_mode::bypass) {
            // If the rule has been bypassed, there is no need to add objects to it.
            return;
        }
        rule_policy.objects.insert(objects.begin(), objects.end());
    }
};

} // namespace ddwaf
