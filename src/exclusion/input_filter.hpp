// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <set>

#include "clock.hpp"
#include "exclusion/object_filter.hpp"
#include "object_store.hpp"
#include "rule.hpp"

namespace ddwaf::exclusion {

class input_filter {
public:
    struct excluded_set {
        const std::set<const core_rule *> &rules;
        object_set objects;
    };

    struct cache_type {
        expression::cache_type expr_cache;
        object_filter::cache_type object_filter_cache;
    };

    input_filter(std::string id, std::shared_ptr<expression> expr,
        std::set<const core_rule *> rule_targets, std::shared_ptr<object_filter> filter);
    input_filter(const input_filter &) = delete;
    input_filter &operator=(const input_filter &) = delete;
    input_filter(input_filter &&) = default;
    input_filter &operator=(input_filter &&) = delete;
    ~input_filter() = default;

    std::optional<excluded_set> match(const object_store &store, cache_type &cache,
        const matcher_mapper &dynamic_matchers, ddwaf::timer &deadline) const;

    std::string_view get_id() { return id_; }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        expr_->get_addresses(addresses);
        filter_->get_addresses(addresses);
    }

    static void invalidate_subcontext_cache(cache_type &cache)
    {
        expression::invalidate_subcontext_cache(cache.expr_cache);
    }

protected:
    std::string id_;
    std::shared_ptr<expression> expr_;
    std::set<const core_rule *> rule_targets_;
    std::shared_ptr<object_filter> filter_;
};

} // namespace ddwaf::exclusion
