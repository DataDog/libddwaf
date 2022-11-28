// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <set>
#include <stack>
#include <vector>

#include <clock.hpp>
#include <exclusion/object_filter.hpp>
#include <manifest.hpp>
#include <object_store.hpp>
#include <rule.hpp>

namespace ddwaf::exclusion {

class input_filter {
public:
    using ptr = std::shared_ptr<input_filter>;

    struct target_specification {
        const std::set<rule::ptr> &rules;
        const std::unordered_set<manifest::target_type> &inputs;
        std::unordered_set<ddwaf_object*> objects;
    };

    struct cache_type {
        bool result{false};
        std::unordered_map<condition::ptr, bool> conditions;
        object_filter::cache_type object_filter_cache;
    };

    input_filter(std::vector<condition::ptr> &&conditions,
            std::set<rule::ptr> &&rule_targets,
            std::unordered_set<manifest::target_type> &&input_targets = {},
            std::optional<object_filter> &&filter = std::nullopt)
        : conditions_(std::move(conditions)), rule_targets_(std::move(rule_targets)),
        input_targets_(std::move(input_targets)), filter_(std::move(filter))
    {}

    std::optional<target_specification> match(const object_store &store,
        const ddwaf::manifest &manifest, cache_type &cache, ddwaf::timer &deadline) const;

protected:
    std::vector<condition::ptr> conditions_;
    const std::set<rule::ptr> rule_targets_;
    const std::unordered_set<manifest::target_type> input_targets_;
    std::optional<object_filter> filter_;
};


} // namespace ddwaf
