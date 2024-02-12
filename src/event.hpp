// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <optional>

#include "condition/base.hpp"
#include "ddwaf.h"
#include "obfuscator.hpp"

namespace ddwaf {

class rule;

struct event {
    const ddwaf::rule *rule{nullptr};
    std::vector<condition_match> matches;
    bool ephemeral{false};
    bool skip_actions{false};
};

using optional_event = std::optional<event>;

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
