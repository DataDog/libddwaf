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

    struct cache_type {
        bool result{false};
        std::optional<std::vector<condition::ptr>::const_iterator> last_cond{};
    };

    rule_filter(
        std::string id, std::vector<condition::ptr> conditions, std::set<rule *> rule_targets);

    optional_ref<const std::unordered_set<rule *>> match(
        const object_store &store, cache_type &cache, ddwaf::timer &deadline) const;

    std::string_view get_id() { return id_; }

    void get_addresses(std::unordered_set<std::string> &addresses) const
    {
        for (const auto &cond : conditions_) {
            for (const auto &target : cond->get_targets()) { addresses.emplace(target.name); }
        }
    }

protected:
    std::string id_;
    std::vector<condition::ptr> conditions_;
    std::unordered_set<rule *> rule_targets_;
};

} // namespace ddwaf::exclusion
