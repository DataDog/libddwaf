// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <event.hpp>
#include <rule.hpp>

#include "compat_memory_resource.hpp"
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ddwaf {

// Collections are used to organize rules depending on their rule.type field. The overall goal
// behind the collection concept is to group rules of a similar nature and only evaluate as many of
// those rules as required to satisfy the criteria defined by the type of collection. For example,
// regular collections stop evaluating rules when there is one match, while priority collections
// stop evaluating rules when all the actions available in the collection have been seen at least
// once (through a match). Priority collections only store rules with actions while regular
// collections only store rules without actions, as a consequence it is possible for both a regular
// collection and a priority collection to exist for the same rule type. Finally, as the suggests,
// priority collections are usually evaluated before regular collections.

// The collection cache is shared by both priority and regular collections,
// this ensures that regular collections for which there is an equivalent
// priority collection of the same type, aren't processed when the respective
// priority collection has already had a match.
struct collection_cache {
    using alloc_type = std::pmr::polymorphic_allocator<std::byte>;
    explicit collection_cache(alloc_type alloc = {}) : rule_cache{alloc}, remaining_actions{alloc}
    {}
    collection_cache(const std::unordered_set<std::string_view> &actions_set, alloc_type alloc)
        : rule_cache{alloc}, remaining_actions{actions_set.cbegin(), actions_set.cend(),
                                 actions_set.bucket_count(), alloc} {};

    bool result{false};
    std::pmr::unordered_map<rule::ptr, rule::cache_type> rule_cache;
    std::pmr::unordered_set<std::string_view> remaining_actions;
};

class collection {
public:
    using object_set = std::pmr::unordered_set<const ddwaf_object *>;
    using cache_type = collection_cache;

    collection() = default;
    virtual ~collection() = default;
    collection(const collection &) = default;
    collection(collection &&) = default;
    collection &operator=(const collection &) = default;
    collection &operator=(collection &&) = default;

    virtual void insert(rule::ptr rule) { rules_.emplace_back(std::move(rule)); }

    virtual void match(std::pmr::vector<event> &events /* output */,
        std::pmr::unordered_set<std::string_view> &seen_actions /* input & output */,
        const object_store &store, collection_cache &cache,
        const std::pmr::unordered_set<ddwaf::rule *> &rules_to_exclude,
        const std::pmr::unordered_map<ddwaf::rule *, object_set> &objects_to_exclude,
        const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
        ddwaf::timer &deadline) const;

    [[nodiscard]] virtual collection_cache get_cache(
        std::pmr::polymorphic_allocator<std::byte> alloc) const
    {
        return collection_cache{alloc};
    }

protected:
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

    void match(std::pmr::vector<event> &events /* output */,
        std::pmr::unordered_set<std::string_view> &seen_actions /* input & output */,
        const object_store &store, collection_cache &cache,
        const std::pmr::unordered_set<ddwaf::rule *> &rules_to_exclude,
        const std::pmr::unordered_map<ddwaf::rule *, object_set> &objects_to_exclude,
        const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
        ddwaf::timer &deadline) const override;

    [[nodiscard]] collection_cache get_cache(
        std::pmr::polymorphic_allocator<std::byte> alloc) const override
    {
        return {actions_, alloc};
    }

protected:
    std::unordered_set<std::string_view> actions_;
};

} // namespace ddwaf
