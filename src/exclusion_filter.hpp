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

    using cache_type = std::unordered_map<std::shared_ptr<condition>, bool>;

    exclusion_filter(std::vector<std::shared_ptr<condition>> &&conditions,
            std::unordered_set<rule::index_type> &&rule_targets):
        conditions_(std::move(conditions)),
        rule_targets_(std::move(rule_targets)) {}

    const std::unordered_set<rule::index_type> &get_rule_targets() const {
        return rule_targets_;
    }

    bool filter(const object_store& store, const ddwaf::manifest &manifest,
        cache_type &cache, ddwaf::timer& deadline) const;

protected:
    std::vector<std::shared_ptr<condition>> conditions_;
    std::unordered_set<rule::index_type> rule_targets_;
};

using exclusion_filter_vector = std::vector<std::shared_ptr<exclusion_filter>>;
} // namespace ddwaf
