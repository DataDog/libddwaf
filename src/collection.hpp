// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "exclusion/rule_filter.hpp"
#include <context_allocator.hpp>
#include <event.hpp>
#include <rule.hpp>

#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ddwaf {

enum class collection_type : uint8_t { none = 0, regular = 1, priority = 2 };

// Collections are used to organize rules depending on their rule.type field. The overall goal
// behind the collection concept is to group rules of a similar nature and only evaluate as many of
// those rules until there is a match. Priority collections and regular collections only differ on
// how they interact with the cache, e.g. a priority collection will try to match even if there has
// already been a match in a regular collection.

// The collection cache is shared by both priority and regular collections,
// this ensures that regular collections for which there is an equivalent
// priority collection of the same type, aren't processed when the respective
// priority collection has already had a match.
struct collection_cache {
    collection_type result{collection_type::none};
    memory::unordered_map<rule *, rule::cache_type> rule_cache;
};

template <typename Derived> class base_collection {
public:
    using object_set = std::unordered_set<const ddwaf_object *>;
    using cache_type = collection_cache;

    base_collection() = default;
    ~base_collection() = default;
    base_collection(const base_collection &) = default;
    base_collection(base_collection &&) noexcept = default;
    base_collection &operator=(const base_collection &) = default;
    base_collection &operator=(base_collection &&) noexcept = default;

    void insert(const std::shared_ptr<rule> &rule) { rules_.emplace_back(rule.get()); }

    void match(memory::vector<event> &events /* output */, const object_store &store,
        collection_cache &cache,
        const memory::unordered_map<ddwaf::rule *, exclusion::filter_mode> &rules_to_exclude,
        const memory::unordered_map<ddwaf::rule *, object_set> &objects_to_exclude,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        ddwaf::timer &deadline) const;

protected:
    std::vector<rule *> rules_{};
};

class collection : public base_collection<collection> {
public:
    static constexpr collection_type type() { return collection_type::regular; }
};

class priority_collection : public base_collection<priority_collection> {
public:
    static constexpr collection_type type() { return collection_type::priority; }
};

} // namespace ddwaf
