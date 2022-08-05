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
#include <utils.h>

namespace ddwaf::rule_processor {

class base
{
public:
    base()          = default;
    virtual ~base() = default;

    virtual std::optional<event::match> match(std::string_view str) const = 0;

    virtual std::optional<event::match> match_object(const ddwaf_object *obj) const {
        if (obj->stringValue == nullptr) { return std::nullopt; }
        return match({obj->stringValue, static_cast<std::size_t>(obj->nbEntries)});
    }

    virtual std::string_view to_string() const { return ""; }

    /* The return value of this function should outlive the function scope,
     * for example, through a constexpr class static string_view initialised
     * with a literal. */
    virtual std::string_view name() const = 0;

    event::match make_event(std::string_view resolved, std::string_view matched) const
    {
        return {
            std::string(resolved), std::string(matched),
            name(), to_string(), {}, {}
        };
    }
};

}

