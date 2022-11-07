// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <set>
#include <vector>

#include <clock.hpp>
#include <manifest.hpp>
#include <object_store.hpp>
#include <rule.hpp>


namespace ddwaf
{

class exclusion_filter {
public:
    struct cache_type {
        bool result{false};
        std::unordered_map<std::shared_ptr<condition>, bool> conditions;
    };

    exclusion_filter(std::vector<std::shared_ptr<condition>> &&conditions,
            std::set<std::shared_ptr<rule>> &&rule_targets):
        conditions_(std::move(conditions)),
        rule_targets_(std::move(rule_targets)) {}

    const std::set<std::shared_ptr<rule>> &get_rule_targets() const {
        return rule_targets_;
    }

    bool match(const object_store& store, const ddwaf::manifest &manifest,
        cache_type &cache, ddwaf::timer& deadline) const;

protected:
    std::vector<std::shared_ptr<condition>> conditions_;
    std::set<std::shared_ptr<rule>> rule_targets_;
};

using exclusion_filter_vector = std::vector<std::shared_ptr<exclusion_filter>>;
} // namespace ddwaf
