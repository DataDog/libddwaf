// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <event.hpp>
#include <rule.hpp>

#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ddwaf {

class collection {
public:
    using object_set = std::unordered_set<const ddwaf_object *>;

    struct cache_type {
        bool result{false};
        std::unordered_map<rule::ptr, rule::cache_type> rule_cache;
    };

    collection() = default;
    virtual ~collection() = default;
    collection(const collection &) = default;
    collection(collection &&) = default;
    collection &operator=(const collection &) = default;
    collection &operator=(collection &&) = default;

    void insert(rule::ptr rule) { rules_.emplace_back(std::move(rule)); }

    void match(std::vector<event> &events, const object_store &store,
        const ddwaf::manifest &manifest, cache_type &cache,
        const std::unordered_set<rule::ptr> &rules_to_exclude,
        const std::unordered_map<rule::ptr, object_set> &objects_to_exclude,
        ddwaf::timer &deadline);

protected:
    std::vector<rule::ptr> rules_{};
};

} // namespace ddwaf
