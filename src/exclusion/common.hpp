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

namespace exclusion {

enum class filter_mode : uint8_t { none = 0, custom = 1, monitor = 2, bypass = 3 };

struct object_set {
    std::unordered_set<object_cache_key> context;
    std::unordered_set<object_cache_key> subcontext;
    bool empty() const { return context.empty() && subcontext.empty(); }
    [[nodiscard]] std::size_t size() const { return context.size() + subcontext.size(); }

    bool contains(object_view obj) const
    {
        return context.contains(obj) || subcontext.contains(obj);
    }
};

struct rule_policy {
    filter_mode mode{filter_mode::none};
    std::string_view action_override;
    std::unordered_set<object_cache_key> objects;
};

struct object_set_ref {
    optional_ref<const std::unordered_set<object_cache_key>> context{std::nullopt};
    optional_ref<const std::unordered_set<object_cache_key>> subcontext{std::nullopt};

    [[nodiscard]] bool empty() const
    {
        return (!context.has_value() || context->get().empty()) &&
               (!subcontext.has_value() || subcontext->get().empty());
    }

    [[nodiscard]] std::size_t size() const
    {
        return (context.has_value() ? context->get().size() : 0) +
               (subcontext.has_value() ? subcontext->get().size() : 0);
    }

    [[nodiscard]] bool contains(object_view obj) const
    {
        return (context.has_value() && context->get().contains(obj)) ||
               (subcontext.has_value() && subcontext->get().contains(obj));
    }
};

struct rule_policy_ref {
    filter_mode mode{filter_mode::none};
    std::string_view action_override;
    object_set_ref objects;
};

struct exclusion_policy {
    std::unordered_map<const core_rule *, rule_policy> context;
    std::unordered_map<const core_rule *, rule_policy> subcontext;

    [[nodiscard]] bool empty() const { return context.empty() && subcontext.empty(); }

    [[nodiscard]] std::size_t size() const { return context.size() + subcontext.size(); }

    bool contains(const core_rule *key) const
    {
        return context.contains(key) || subcontext.contains(key);
    }

    rule_policy_ref find(const core_rule *key) const
    {
        auto p_it = context.find(key);
        auto e_it = subcontext.find(key);

        if (p_it == context.end()) {
            if (e_it == subcontext.end()) {
                return {.mode = filter_mode::none,
                    .action_override = {},
                    .objects = {.context = std::nullopt, .subcontext = std::nullopt}};
            }

            const auto &e_policy = e_it->second;
            return {.mode = e_policy.mode,
                .action_override = e_policy.action_override,
                .objects = {.context = std::nullopt, .subcontext = e_policy.objects}};
        }

        if (e_it == subcontext.end()) {
            const auto &p_policy = p_it->second;
            p_policy.objects.size();
            return {.mode = p_policy.mode,
                .action_override = p_policy.action_override,
                .objects = {.context = p_policy.objects, .subcontext = std::nullopt}};
        }

        const auto &p_policy = p_it->second;
        const auto &e_policy = e_it->second;

        const auto &effective_policy = p_policy.mode > e_policy.mode ? p_policy : e_policy;
        return {.mode = effective_policy.mode,
            .action_override = effective_policy.action_override,
            .objects = {.context = p_policy.objects, .subcontext = e_policy.objects}};
    }

    void add_rule_exclusion(
        const core_rule *rule, filter_mode mode, std::string_view action, evaluation_scope scope)
    {
        auto &rule_policy = scope.is_context() ? context : subcontext;

        auto &policy = rule_policy[rule];
        // Bypass has precedence over monitor
        if (policy.mode < mode) {
            policy.mode = mode;
            policy.action_override = action;
        }
    }

    void add_input_exclusion(const core_rule *rule, const object_set &objects)
    {
        if (!objects.context.empty()) {
            auto &rule_policy = context[rule];
            if (rule_policy.mode == filter_mode::bypass) {
                // If the rule has been bypassed, there is no need to
                // add context or subcontext objects to it.
                return;
            }
            rule_policy.objects.insert(objects.context.begin(), objects.context.end());
        } else {
            auto it = context.find(rule);
            if (it != context.end() && it->second.mode == filter_mode::bypass) {
                return;
            }
        }

        if (!objects.subcontext.empty()) {
            auto &rule_policy = subcontext[rule];
            // Bypass has precedence over monitor
            if (rule_policy.mode != filter_mode::bypass) {
                rule_policy.objects.insert(objects.subcontext.begin(), objects.subcontext.end());
            }
        }
    }
};

} // namespace exclusion
} // namespace ddwaf
