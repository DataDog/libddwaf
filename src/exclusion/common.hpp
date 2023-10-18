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

enum class filter_mode : uint8_t { none = 0, monitor = 1, bypass = 2 };

struct object_set {
    std::unordered_set<const ddwaf_object *> persistent;
    std::unordered_set<const ddwaf_object *> ephemeral;
    bool empty() const { return persistent.empty() && ephemeral.empty(); }
};

struct rule_policy {
    filter_mode mode{filter_mode::none};
    std::unordered_set<const ddwaf_object *> objects{};
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
    object_set_ref objects;
};

struct context_policy {
    std::unordered_map<rule *, rule_policy> persistent;
    std::unordered_map<rule *, rule_policy> ephemeral;

    rule_policy_ref find(rule *key) const
    {
        auto p_it = persistent.find(key);
        auto e_it = ephemeral.find(key);

        if (p_it == persistent.end()) {
            if (e_it == ephemeral.end()) {
                return {filter_mode::none, {std::nullopt, std::nullopt}};
            }

            const auto &e_policy = e_it->second;
            return {e_policy.mode, {std::nullopt, e_policy.objects}};
        }

        if (e_it == ephemeral.end()) {
            const auto &p_policy = p_it->second;
            p_policy.objects.size();
            return {p_policy.mode, {p_policy.objects, std::nullopt}};
        }

        const auto &p_policy = p_it->second;
        const auto &e_policy = e_it->second;
        auto mode = p_policy.mode > e_policy.mode ? p_policy.mode : e_policy.mode;

        return {mode, {p_policy.objects, e_policy.objects}};
    }
};

} // namespace exclusion
} // namespace ddwaf
