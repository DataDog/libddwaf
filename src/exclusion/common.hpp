// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <unordered_set>

#include "context_allocator.hpp"
#include "ddwaf.h"
#include "utils.hpp"

namespace ddwaf {

class rule;

namespace exclusion {

enum class filter_mode : uint8_t { none = 0, monitor = 1, bypass = 2 };

struct object_set {
    std::unordered_set<const ddwaf_object *> persistent;
    std::unordered_set<const ddwaf_object *> ephemeral;

    bool empty() const { return persistent.empty() && ephemeral.empty(); }
    std::size_t size() const { return persistent.size() + ephemeral.size(); }
    void add_from(const object_set &objects)
    {
        persistent.insert(objects.persistent.begin(), objects.persistent.end());
        ephemeral.insert(objects.ephemeral.begin(), objects.ephemeral.end());
    }
    bool contains(const ddwaf_object *obj) const
    {
        return persistent.contains(obj) || ephemeral.contains(obj);
    }
};

struct rule_policy {
    filter_mode mode;
    std::unordered_set<const ddwaf_object *> objects;
};

struct rule_policy_ref {
    filter_mode mode{filter_mode::none};
    struct {
        optional_ref<std::unordered_set<const ddwaf_object *>> persistent{};
        optional_ref<std::unordered_set<const ddwaf_object *>> ephemeral{};
    } objects;
};

struct context_policy {
    std::unordered_map<rule *, rule_policy> persistent;
    std::unordered_map<rule *, rule_policy> ephemeral;

    rule_policy_ref find(rule *key)
    {
        auto p_it = persistent.find(key);
        auto e_it = ephemeral.find(key);

        if (p_it == persistent.end()) {
            if (e_it == ephemeral.end()) {
                return {};
            }

            auto e_policy = e_it->second;
            return {e_policy.mode, {std::nullopt, e_policy.objects}};
        }

        if (e_it == ephemeral.end()) {
            auto p_policy = p_it->second;
            return {p_policy.mode, {p_policy.objects, std::nullopt}};
        }

        auto p_policy = p_it->second;
        auto e_policy = e_it->second;
        auto mode = p_policy.mode > e_policy.mode ? p_policy.mode : e_policy.mode;

        return {mode, {p_policy.objects, e_policy.objects}};
    }
};

} // namespace exclusion
} // namespace ddwaf
