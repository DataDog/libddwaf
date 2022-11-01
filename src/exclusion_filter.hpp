// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <unordered_set>
#include <vector>

#include <clock.hpp>
#include <manifest.hpp>
#include <object_store.hpp>
#include <rule.hpp>


namespace ddwaf
{

class exclusion_filter {
public:
    using index_type = uint32_t;

    exclusion_filter(index_type index, std::vector<condition> &&conditions,
            std::unordered_set<rule::index_type> &&rule_targets):
        index_(index), conditions_(std::move(conditions)),
        rule_targets_(std::move(rule_targets)) {}

    const std::unordered_set<rule::index_type> &get_rule_targets() {
        return targets_;
    }

    bool match(const object_store& store, const ddwaf::manifest &manifest,
        ddwaf::timer& deadline) const;

protected:
    index_type index_;
    std::vector<condition> conditions_;
    std::unordered_set<rule::index_type> rule_targets_;
    std::unordered_set<ddwaf::manifest::target_type> targets_;
};

} // namespace ddwaf
