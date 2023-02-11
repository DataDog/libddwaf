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
#include <object_store.hpp>
#include <rule.hpp>

namespace ddwaf::exclusion {
class rule_filter {
public:
    using ptr = std::shared_ptr<rule_filter>;
    using optional_set = std::optional<std::reference_wrapper<const std::set<rule::ptr>>>;

    struct cache_type {
        bool result{false};
        std::unordered_map<condition::ptr, bool> conditions;
    };

    rule_filter(std::string id, std::vector<condition::ptr> conditions,
        std::set<rule::ptr> rule_targets);

    std::unordered_set<rule::ptr> match(const object_store &store,
        cache_type &cache, ddwaf::timer &deadline) const;

    std::string_view get_id() { return id_; }

protected:
    std::string id_;
    std::vector<condition::ptr> conditions_;
    std::unordered_set<rule::ptr> rule_targets_;
};

} // namespace ddwaf::exclusion
