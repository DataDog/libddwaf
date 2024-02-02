// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "ddwaf.h"
#include "obfuscator.hpp"

namespace ddwaf {

class rule;

struct event {
    struct univariate_match {
        std::string resolved;
        std::string matched;
        std::string_view operator_name;
        std::string_view operator_value;
        std::string_view address;
        std::vector<std::string> key_path;
        bool ephemeral{false};
    };

    struct multivariate_match {
        struct condition_argument {
            std::string_view name;
            std::string resolved;
            std::string_view address;
            std::vector<std::string> key_path;
        };
        std::vector<condition_argument> arguments;
        std::string matched;
        std::string_view operator_name;
        std::string_view operator_value;
        bool ephemeral{false};
    };

    using match = std::variant<std::monostate, univariate_match, multivariate_match>;
    const ddwaf::rule *rule{nullptr};
    std::vector<match> matches;
    bool ephemeral{false};
    bool skip_actions{false};
};

inline bool is_ephemeral_match(const event::match &m)
{
    if (std::holds_alternative<event::univariate_match>(m)) {
        return std::get<event::univariate_match>(m).ephemeral;
    }
    if (std::holds_alternative<event::multivariate_match>(m)) {
        return std::get<event::multivariate_match>(m).ephemeral;
    }

    return false;
}
using optional_event = std::optional<event>;
using optional_match = std::optional<event::match>;

class event_serializer {
public:
    explicit event_serializer(const ddwaf::obfuscator &event_obfuscator)
        : obfuscator_(event_obfuscator)
    {}

    void serialize(const std::vector<event> &events, ddwaf_result &output) const;

protected:
    const ddwaf::obfuscator &obfuscator_;
};

} // namespace ddwaf
