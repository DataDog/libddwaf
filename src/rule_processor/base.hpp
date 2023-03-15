// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <ddwaf.h>
#include <event.hpp>
#include <utils.hpp>

namespace ddwaf::rule_processor {

class base {
public:
    using allocator = std::pmr::polymorphic_allocator<std::byte>;
    using ptr = std::shared_ptr<base>;

    base() = default;
    virtual ~base() = default;
    base(const base &) = default;
    base(base &&) = default;
    base &operator=(const base &) = default;
    base &operator=(base &&) = default;

    std::optional<event::match> match_object(const ddwaf_object *obj) const
    {
        if (obj->stringValue == nullptr) {
            return std::nullopt;
        }
        return do_match(
            {obj->stringValue, static_cast<std::size_t>(obj->nbEntries)}, new_del_alloc);
    }

    [[nodiscard]] std::optional<event::match> match(std::string_view str)
    {
        return do_match(str, new_del_alloc);
    }

    [[nodiscard]] virtual std::string_view to_string() const { return ""; }

    /* The return value of this function should outlive the function scope,
     * for example, through a constexpr class static string_view initialised
     * with a literal. */
    [[nodiscard]] virtual std::string_view name() const = 0;

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    [[nodiscard]] event::match make_event(
        std::string_view resolved, std::string_view matched, allocator alloc) const
    {
        return {resolved, matched, name(), to_string(), alloc};
    }

protected:
    // Interface could be modified to pass along the allocator used for the
    // context. This would avoid some copies down the line, as the match is
    // stored inside the context
    static inline const auto new_del_alloc = std::pmr::new_delete_resource();

    [[nodiscard]] virtual std::optional<event::match> do_match(
        std::string_view str, allocator alloc) const = 0;
};

} // namespace ddwaf::rule_processor
