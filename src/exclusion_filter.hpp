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
#include <input_filter.hpp>
#include <manifest.hpp>
#include <object_store.hpp>
#include <rule.hpp>

namespace ddwaf {

class exclusion_filter {
public:
    using ptr = std::shared_ptr<exclusion_filter>;

    struct cache_type {
        bool result{false};
        std::unordered_map<condition::ptr, bool> conditions;
    };

    exclusion_filter(std::vector<condition::ptr> &&conditions, std::set<rule::ptr> &&rule_targets,
      input_filter::input_set && inputs)
        : conditions_(std::move(conditions)), rule_targets_(std::move(rule_targets)),
          inputs_(std::move(inputs))
    {}

    [[nodiscard]] const std::set<rule::ptr> &get_rule_targets() const { return rule_targets_; }
    [[nodiscard]] const input_filter::input_set &get_inputs() const { return inputs_; }

    bool match(const object_store &store, const ddwaf::manifest &manifest, cache_type &cache,
        ddwaf::timer &deadline) const;

protected:
    std::vector<condition::ptr> conditions_;
    std::set<rule::ptr> rule_targets_;
    input_filter::input_set inputs_;
};


} // namespace ddwaf
