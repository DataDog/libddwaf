// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <unordered_set>

#include "context_allocator.hpp"
#include "ddwaf.h"
#include "log.hpp"
#include "utils.hpp"

namespace ddwaf {

class rule;

namespace exclusion {

enum class filter_mode : uint8_t { none = 0, custom = 1, monitor = 2, bypass = 3 };

struct object_set {
    std::unordered_set<const ddwaf_object *> persistent;
    std::unordered_set<const ddwaf_object *> ephemeral;
    bool empty() const { return persistent.empty() && ephemeral.empty(); }
    [[nodiscard]] std::size_t size() const { return persistent.size() + ephemeral.size(); }

    bool contains(const ddwaf_object *obj) const
    {
        return persistent.contains(obj) || ephemeral.contains(obj);
    }
};

struct rule_policy {
    filter_mode mode{filter_mode::none};
    std::string_view action;
    std::unordered_set<const ddwaf_object *> objects;
};

struct object_set_ref {
    optional_ref<const std::unordered_set<const ddwaf_object *>> persistent{std::nullopt};
    optional_ref<const std::unordered_set<const ddwaf_object *>> ephemeral{std::nullopt};

    [[nodiscard]] bool empty() const
    {
        return (!persistent.has_value() || persistent->get().empty()) &&
               (!ephemeral.has_value() || ephemeral->get().empty());
    }

    [[nodiscard]] std::size_t size() const
    {
        return (persistent.has_value() ? persistent->get().size() : 0) +
               (ephemeral.has_value() ? ephemeral->get().size() : 0);
    }

    bool contains(const ddwaf_object *obj) const
    {
        return (persistent.has_value() && persistent->get().contains(obj)) ||
               (ephemeral.has_value() && ephemeral->get().contains(obj));
    }
};

struct rule_policy_ref {
    filter_mode mode{filter_mode::none};
    std::string_view action;
    object_set_ref objects;
};

struct context_policy {
    std::unordered_map<const rule *, rule_policy> persistent;
    std::unordered_map<const rule *, rule_policy> ephemeral;

    [[nodiscard]] bool empty() const { return persistent.empty() && ephemeral.empty(); }

    [[nodiscard]] std::size_t size() const { return persistent.size() + ephemeral.size(); }

    bool contains(const rule *key) const
    {
        return persistent.contains(key) || ephemeral.contains(key);
    }

    rule_policy_ref find(const rule *key) const
    {
        auto p_it = persistent.find(key);
        auto e_it = ephemeral.find(key);

        if (p_it == persistent.end()) {
            if (e_it == ephemeral.end()) {
                return {filter_mode::none, {}, {std::nullopt, std::nullopt}};
            }

            const auto &e_policy = e_it->second;
            return {e_policy.mode, e_policy.action, {std::nullopt, e_policy.objects}};
        }

        if (e_it == ephemeral.end()) {
            const auto &p_policy = p_it->second;
            p_policy.objects.size();
            return {p_policy.mode, p_policy.action, {p_policy.objects, std::nullopt}};
        }

        const auto &p_policy = p_it->second;
        const auto &e_policy = e_it->second;

        if (p_policy.mode > e_policy.mode) {
            return {p_policy.mode, p_policy.action, {p_policy.objects, e_policy.objects}};
        }
        return {e_policy.mode, e_policy.action, {p_policy.objects, e_policy.objects}};
    }

    void add_rule_exclusion(const ddwaf::rule *rule, filter_mode mode, std::string_view action,
        bool ephemeral_exclusion)
    {
        auto &rule_policy = ephemeral_exclusion ? ephemeral : persistent;

        auto &policy = rule_policy[rule];
        // Bypass has precedence over monitor
        if (policy.mode < mode) {
            policy.mode = mode;
            policy.action = action;
        }
    }

    void add_input_exclusion(const ddwaf::rule *rule, const object_set &objects)
    {
        if (!objects.persistent.empty()) {
            auto &rule_policy = persistent[rule];
            if (rule_policy.mode == filter_mode::bypass) {
                // If the rule has been bypassed, there is no need to
                // add persistent or ephemeral objects to it.
                return;
            }
            rule_policy.objects.insert(objects.persistent.begin(), objects.persistent.end());
        } else {
            auto it = persistent.find(rule);
            if (it != persistent.end() && it->second.mode == filter_mode::bypass) {
                return;
            }
        }

        if (!objects.ephemeral.empty()) {
            auto &rule_policy = ephemeral[rule];
            // Bypass has precedence over monitor
            if (rule_policy.mode != filter_mode::bypass) {
                rule_policy.objects.insert(objects.ephemeral.begin(), objects.ephemeral.end());
            }
        }
    }
};

} // namespace exclusion
} // namespace ddwaf
