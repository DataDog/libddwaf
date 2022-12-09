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

// The collection cache is shared by both priority and regular collections,
// this ensures that regular collections aren't processed when the respective
// priority collection has already had a match.
struct collection_cache {
    bool result{false};
    std::unordered_map<rule::ptr, rule::cache_type> rule_cache;
    std::unordered_set<std::string_view> remaining_actions;
};

class collection {
public:
    using object_set = std::unordered_set<const ddwaf_object *>;
    using cache_type = collection_cache;

    collection() = default;
    virtual ~collection() = default;
    collection(const collection &) = default;
    collection(collection &&) = default;
    collection &operator=(const collection &) = default;
    collection &operator=(collection &&) = default;

    virtual void insert(rule::ptr rule) { rules_.emplace_back(std::move(rule)); }

    void match(std::vector<event> &events, const object_store &store,
        const ddwaf::manifest &manifest, collection_cache &cache,
        const std::unordered_set<rule::ptr> &rules_to_exclude,
        const std::unordered_map<rule::ptr, object_set> &objects_to_exclude,
        ddwaf::timer &deadline);

    virtual collection_cache get_cache() { return {}; }

protected:
    static std::optional<event> match_rule(const rule::ptr &rule, const object_store &store,
        const ddwaf::manifest &manifest, std::unordered_map<rule::ptr, rule::cache_type> &cache,
        const std::unordered_set<rule::ptr> &rules_to_exclude,
        const std::unordered_map<rule::ptr, object_set> &objects_to_exclude,
        ddwaf::timer &deadline);

    std::vector<rule::ptr> rules_{};
};

class priority_collection : public collection {
public:
    priority_collection() = default;
    ~priority_collection() override = default;
    priority_collection(const priority_collection &) = default;
    priority_collection(priority_collection &&) = default;
    priority_collection &operator=(const priority_collection &) = default;
    priority_collection &operator=(priority_collection &&) = default;

    void insert(rule::ptr rule) override
    {
        actions_.insert(rule->actions.begin(), rule->actions.end());
        rules_.emplace_back(std::move(rule));
    }

    void match(std::vector<event> &events, std::unordered_set<std::string_view> &seen_actions,
        const object_store &store, const ddwaf::manifest &manifest, collection_cache &cache,
        const std::unordered_set<rule::ptr> &rules_to_exclude,
        const std::unordered_map<rule::ptr, object_set> &objects_to_exclude,
        ddwaf::timer &deadline);

    collection_cache get_cache() override { return {false, {}, actions_}; }

protected:
    std::unordered_set<std::string_view> actions_;
};

} // namespace ddwaf
