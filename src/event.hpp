// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <optional>

#include "action_mapper.hpp"
#include "condition/base.hpp"
#include "ddwaf.h"
#include "obfuscator.hpp"

namespace ddwaf {

class base_rule;

struct event {
    const ddwaf::base_rule *rule{nullptr};
    std::vector<condition_match> matches;
    bool ephemeral{false};
    std::string_view action_override;
};

using optional_event = std::optional<event>;

class event_serializer {
public:
    explicit event_serializer(
        const ddwaf::obfuscator &event_obfuscator, const action_mapper &actions)
        : obfuscator_(event_obfuscator), actions_(actions)
    {}

    void serialize(const std::vector<event> &events, ddwaf_result &output) const;

protected:
    const ddwaf::obfuscator &obfuscator_;
    const action_mapper &actions_;
};

} // namespace ddwaf
