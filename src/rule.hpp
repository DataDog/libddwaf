// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "compat_memory_resource.hpp"
#include <atomic>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <PWTransformer.h>
#include <clock.hpp>
#include <condition.hpp>
#include <event.hpp>
#include <iterator.hpp>
#include <object_store.hpp>
#include <parser/specification.hpp>
#include <rule_processor/base.hpp>

namespace ddwaf {

class rule {
public:
    using ptr = std::shared_ptr<rule>;

    struct cache_type {
        using allocator_type = std::pmr::polymorphic_allocator<std::byte>;

        explicit cache_type(allocator_type alloc = {}) : matches{alloc} {}
        cache_type(const cache_type &o, allocator_type alloc)
            : result{o.result}, matches{o.matches, alloc}, last_non_matched_cond{
                                                               o.last_non_matched_cond}
        {}
        cache_type(cache_type &&o, allocator_type alloc)
            : result{o.result}, matches{std::move(o.matches), alloc}, last_non_matched_cond{
                                                                          o.last_non_matched_cond}
        {}

        cache_type(const cache_type &) = default;
        cache_type(cache_type &&) = default;
        cache_type &operator=(const cache_type &) = default;
        cache_type &operator=(cache_type &&) = default;
        ~cache_type() = default;

        bool result{false};
        std::pmr::vector<event::match> matches;
        std::optional<std::vector<condition::ptr>::const_iterator> last_non_matched_cond{};
    };

    // TODO: make fields protected, add getters, follow conventions, add cache
    //       move condition matching from context.

    rule(std::string id_, std::string name_, std::unordered_map<std::string, std::string> tags_,
        std::vector<condition::ptr> conditions_, std::vector<std::string> actions_ = {},
        bool enabled_ = true);

    rule(const rule &) = delete;
    rule &operator=(const rule &) = delete;

    rule(rule &&rhs) noexcept
        : enabled(rhs.enabled), id(std::move(rhs.id)), name(std::move(rhs.name)),
          tags(std::move(rhs.tags)), conditions(std::move(rhs.conditions)),
          actions(std::move(rhs.actions))
    {}

    rule &operator=(rule &&rhs) noexcept
    {
        enabled = rhs.enabled;
        id = std::move(rhs.id);
        name = std::move(rhs.name);
        tags = std::move(rhs.tags);
        conditions = std::move(rhs.conditions);
        actions = std::move(rhs.actions);
        return *this;
    }

    ~rule() = default;

    std::optional<event> match(const object_store &store, cache_type &cache,
        const std::pmr::unordered_set<const ddwaf_object *> &objects_excluded,
        const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
        ddwaf::timer &deadline) const;

    [[nodiscard]] bool is_enabled() const { return enabled; }
    void toggle(bool value) { enabled = value; }

    [[nodiscard]] std::string_view get_tag(const std::string &tag) const
    {
        auto it = tags.find(tag);
        return it == tags.end() ? std::string_view() : it->second;
    }

    bool enabled{true};
    std::string id;
    std::string name;
    std::unordered_map<std::string, std::string> tags;
    std::vector<condition::ptr> conditions;
    std::vector<std::string> actions;
};

} // namespace ddwaf
