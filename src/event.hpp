// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "memory_resource.hpp"
#include <ddwaf.h>
#include <initializer_list>
#include <memory>
#include <obfuscator.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>

namespace ddwaf {

struct event {
    struct match {
        using allocator_type = std::pmr::polymorphic_allocator<std::byte>;

        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        match(std::string_view resolved, std::string_view matched, std::string_view operator_name,
            std::string_view operator_value, allocator_type allocator = {})
            : resolved{resolved, allocator}, matched{matched, allocator},
              operator_name{operator_name}, operator_value{operator_value}, key_path{allocator}
        {}

        // used in tests only
        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        match(std::string_view resolved, std::string_view matched, std::string_view operator_name,
            std::string_view operator_value, std::string_view source,
            std::initializer_list<std::pmr::string> key_path, allocator_type allocator = {})
            : resolved{resolved, allocator}, matched{matched, allocator},
              operator_name{operator_name},
              operator_value{operator_value}, source{source}, key_path{key_path, allocator}
        {}
        match(const match &o, allocator_type alloc)
            : resolved{o.resolved, alloc}, matched{o.matched, alloc},
              operator_name{o.operator_name},
              operator_value{o.operator_value}, source{o.source}, key_path{o.key_path, alloc}
        {}
        match(match &&o, allocator_type alloc)
            : resolved{std::move(o.resolved), alloc}, matched{std::move(o.matched), alloc},
              operator_name{o.operator_name}, operator_value{o.operator_value}, source{o.source},
              key_path{std::move(o.key_path), alloc}
        {}

        match(const match &) = default;
        match(match &&) = default;
        match &operator=(const match &) = default;
        match &operator=(match &&) = default;
        ~match() = default;

        std::pmr::string resolved;
        std::pmr::string matched;
        std::string_view operator_name;
        std::string_view operator_value;
        std::string_view source;
        std::pmr::vector<std::pmr::string> key_path;
    };

    using allocator_type = std::pmr::polymorphic_allocator<std::byte>;

    explicit event(allocator_type allocator = {}) : actions{allocator}, matches{allocator} {}

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    event(std::string_view id, std::string_view name, std::string_view type,
        std::string_view category, std::pmr::vector<std::string_view> actions,
        std::pmr::vector<match> matches, allocator_type alloc)
        : id{id}, name{name}, type{type}, category{category}, actions{std::move(actions), alloc},
          matches{std::move(matches), alloc}
    {}
    event(const event &oevent, allocator_type alloc)
        : id{oevent.id}, name{oevent.name}, type{oevent.type}, category{oevent.category},
          actions{oevent.actions, alloc}, matches{oevent.matches, alloc}
    {}
    event(event &&oevent, allocator_type alloc)
        : id{oevent.id}, name{oevent.name}, type{oevent.type}, category{oevent.category},
          actions{std::move(oevent.actions), alloc}, matches{std::move(oevent.matches), alloc}
    {}

    event(const event &) = default;
    event(event &&) = default;
    event &operator=(const event &) = default;
    event &operator=(event &&) = default;
    ~event() = default;

    std::string_view id;
    std::string_view name;
    std::string_view type;
    std::string_view category;
    std::pmr::vector<std::string_view> actions;
    std::pmr::vector<match> matches;
};
static_assert(std::uses_allocator_v<event, std::pmr::polymorphic_allocator<std::byte>> != 0U);
static_assert(
    std::uses_allocator_v<event::match, std::pmr::polymorphic_allocator<std::byte>> != 0U);

using optional_event = std::optional<event>;
using optional_match = std::optional<event::match>;

class event_serializer {
public:
    explicit event_serializer(const ddwaf::obfuscator &event_obfuscator)
        : obfuscator_(event_obfuscator)
    {}

    void serialize(const std::pmr::vector<event> &events,
        const std::pmr::unordered_set<std::string_view> &actions, ddwaf_result &output) const;

protected:
    const ddwaf::obfuscator &obfuscator_;
};

} // namespace ddwaf
