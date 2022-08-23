// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <rule_data_dispatcher.hpp>

namespace ddwaf::rule_data {

namespace {



}
dispatcher dispatcher_builder::build(ddwaf::rule_vector &rules)
{
    for (auto &entry : entries_) {
        if (entry.rule_idx >= rules.size() { continue; }

        auto &rule = rules[entry.rule_idx];
        if (entry.cond_idx >= rule.conditions.size()) { continue; }

        auto &condition = rule.conditions[entry.cond_idx];


    }
}

}
