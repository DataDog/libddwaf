// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "object.hpp"
#include "utils.hpp"

namespace ddwaf {

class core_rule;

enum class filter_mode : uint8_t { none = 0, custom = 1, monitor = 2, bypass = 3 };

using object_set = std::unordered_set<object_cache_key>;

// Sorts the rules targeted by a filter by address and removes duplicates. The
// builder already provides them in this form, in which case this is a single
// linear check.
inline std::vector<const core_rule *> normalize_rule_targets(std::vector<const core_rule *> rules)
{
    constexpr std::less<const core_rule *> less;
    if (std::adjacent_find(rules.begin(), rules.end(), [&](const auto *lhs, const auto *rhs) {
            return !less(lhs, rhs);
        }) != rules.end()) {
        std::sort(rules.begin(), rules.end(), less);
        rules.erase(std::unique(rules.begin(), rules.end()), rules.end());
    }
    return rules;
}

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

    // Policy from which this one derives, if any, e.g. that of the context of
    // a subcontext. A derived policy only contains the rules whose policy it
    // has modified, starting from a copy of the upstream one, and reads the
    // others from the upstream policy, which must neither be modified nor
    // destroyed during its lifetime. The upstream policy can't be derived.
    const exclusion_policy *upstream{nullptr};

    static exclusion_policy derive(const exclusion_policy &upstream)
    {
        exclusion_policy derived;
        derived.upstream = &upstream;
        return derived;
    }

    [[nodiscard]] bool empty() const
    {
        return per_rule.empty() && (upstream == nullptr || upstream->empty());
    }

    [[nodiscard]] std::size_t size() const
    {
        auto count = per_rule.size();
        if (upstream != nullptr) {
            for (const auto &[rule, policy] : upstream->per_rule) {
                count += static_cast<std::size_t>(!per_rule.contains(rule));
            }
        }
        return count;
    }

    bool contains(const core_rule *key) const
    {
        return per_rule.contains(key) || (upstream != nullptr && upstream->contains(key));
    }

    rule_policy_ref find(const core_rule *key) const
    {
        auto it = per_rule.find(key);
        if (it == per_rule.end()) {
            if (upstream != nullptr) {
                return upstream->find(key);
            }
            return {.mode = filter_mode::none, .action_override = {}, .objects = std::nullopt};
        }

        const auto &policy = it->second;
        return {.mode = policy.mode,
            .action_override = policy.action_override,
            .objects = policy.objects};
    }

    void add_rule_exclusion(const core_rule *rule, filter_mode mode, std::string_view action)
    {
        if (const auto *policy = find_upstream_only(rule);
            policy != nullptr && policy->mode >= mode) {
            // No change to the upstream policy
            return;
        }

        auto &policy = get_writable(rule);
        // Bypass has precedence over monitor
        if (policy.mode < mode) {
            policy.mode = mode;
            policy.action_override = action;
        }
    }

    void add_input_exclusion(const core_rule *rule, const object_set &objects)
    {
        if (const auto *policy = find_upstream_only(rule);
            policy != nullptr && policy->mode == filter_mode::bypass) {
            // If the rule has been bypassed, there is no need to add objects to it.
            return;
        }

        auto &rule_policy = get_writable(rule);
        if (rule_policy.mode == filter_mode::bypass) {
            // If the rule has been bypassed, there is no need to add objects to it.
            return;
        }
        rule_policy.objects.insert(objects.begin(), objects.end());
    }

protected:
    // Returns the upstream policy of a rule this policy hasn't modified, if any
    [[nodiscard]] const rule_policy *find_upstream_only(const core_rule *rule) const
    {
        if (upstream == nullptr || per_rule.contains(rule)) {
            return nullptr;
        }

        auto it = upstream->per_rule.find(rule);
        return it != upstream->per_rule.end() ? &it->second : nullptr;
    }

    rule_policy &get_writable(const core_rule *rule)
    {
        auto [it, inserted] = per_rule.try_emplace(rule);
        if (inserted && upstream != nullptr) {
            if (auto upstream_it = upstream->per_rule.find(rule);
                upstream_it != upstream->per_rule.end()) {
                it->second = upstream_it->second;
            }
        }
        return it->second;
    }
};

} // namespace ddwaf
