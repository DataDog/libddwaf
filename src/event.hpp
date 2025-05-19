// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "action_mapper.hpp"
#include "attribute_collector.hpp"
#include "ddwaf.h"
#include "obfuscator.hpp"
#include "rule.hpp"

namespace ddwaf {

// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
struct result_components {
    ddwaf_object &events;
    ddwaf_object &actions;
    ddwaf_object &duration;
    ddwaf_object &timeout;
    ddwaf_object &attributes;
    ddwaf_object &keep;
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

class event_serializer {
public:
    explicit event_serializer(
        const ddwaf::obfuscator &event_obfuscator, const action_mapper &actions)
        : obfuscator_(event_obfuscator), actions_(actions)
    {}

    void serialize(std::vector<rule_result> &results, attribute_collector &collector,
        result_components output) const;

protected:
    const ddwaf::obfuscator &obfuscator_;
    const action_mapper &actions_;
};

} // namespace ddwaf
