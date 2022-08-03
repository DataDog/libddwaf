// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <obfuscator.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace ddwaf
{

struct event
{
    struct match
    {
        std::string resolved;
        std::string matched;
        std::string_view operator_name;
        std::string_view operator_value;
        std::string_view source;
        std::vector<std::string> key_path;
    };

    std::string_view id;
    std::string_view name;
    std::string_view type;
    std::string_view category;
    std::vector<std::string_view> actions;
    std::vector<match> matches;
};

class event_serializer
{
public:
    event_serializer(const ddwaf::obfuscator &event_obfuscator):
        obfuscator_(event_obfuscator) {}

    void insert(event &&e) {
        events_.emplace_back(std::move(e));
    }

    bool has_events() const { return !events_.empty(); }

    void serialize(ddwaf_result &output) const;

protected:
    std::vector<event> events_;
    const ddwaf::obfuscator &obfuscator_;
};

}
