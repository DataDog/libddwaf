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
        std::unordered_set<const ddwaf_object *> objects;
    };

    struct cache_type {
        using allocator_type = std::pmr::polymorphic_allocator<std::byte>;

        explicit cache_type(allocator_type alloc = {})
            : conditions{alloc}, object_filter_cache{alloc} {};
        cache_type(const cache_type &o, allocator_type alloc)
            : result{o.result}, conditions{o.conditions, alloc}, object_filter_cache{
                                                                     o.object_filter_cache, alloc}
        {}
        cache_type(cache_type &&o, allocator_type alloc)
            : result{o.result}, conditions{std::move(o.conditions), alloc},
              object_filter_cache{std::move(o.object_filter_cache), alloc}
        {}

        bool result{false};
        std::pmr::unordered_map<condition::ptr, bool> conditions;
        object_filter::cache_type object_filter_cache;
    };

    input_filter(std::string id, std::vector<condition::ptr> conditions,
        std::set<rule *> rule_targets, std::shared_ptr<object_filter> filter);

    std::optional<excluded_set> match(
        const object_store &store, cache_type &cache, ddwaf::timer &deadline) const;

    std::string_view get_id() { return id_; }

protected:
    std::string id_;
    std::vector<condition::ptr> conditions_;
    const std::set<rule *> rule_targets_;
    std::shared_ptr<object_filter> filter_;
};

} // namespace ddwaf::exclusion
