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
#include <object_store.hpp>
#include <rule.hpp>

namespace ddwaf::exclusion {

class input_filter {
public:
    using ptr = std::shared_ptr<input_filter>;

    struct excluded_set {
        const std::set<rule *> &rules;
        memory::unordered_set<const ddwaf_object *> objects;
    };

    struct cache_type {
        expression::cache_type expr_cache;
        object_filter::cache_type object_filter_cache;
    };

    input_filter(std::string id, expression::ptr expr, std::set<rule *> rule_targets,
        std::shared_ptr<object_filter> filter);

    std::optional<excluded_set> match(
        const object_store &store, cache_type &cache, ddwaf::timer &deadline) const;

    std::string_view get_id() { return id_; }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        expr_->get_addresses(addresses);
        filter_->get_addresses(addresses);
    }

protected:
    std::string id_;
    expression::ptr expr_;
    const std::set<rule *> rule_targets_;
    std::shared_ptr<object_filter> filter_;
};

} // namespace ddwaf::exclusion
