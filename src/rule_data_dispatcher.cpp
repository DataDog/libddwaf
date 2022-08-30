// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <rule_data_dispatcher.hpp>
#include <rule_processor/ip_match.hpp>
#include <rule_processor/exact_match.hpp>

namespace ddwaf::rule_data {

dispatcher dispatcher_builder::build(ddwaf::rule_vector &rules)
{
    dispatcher d;
    for (auto &entry : entries_) {
        if (entry.rule_idx >= rules.size()) { continue; }

        auto &rule = rules[entry.rule_idx];
        if (entry.cond_idx >= rule.conditions.size()) { continue; }

        auto &condition = rule.conditions[entry.cond_idx];
        auto processor_name = condition.processor_name();

        try {
            if (processor_name == "ip_match") {
                d.register_condition<rule_processor::ip_match>(entry.id, condition);
            } else if (processor_name == "exact_match") {
                d.register_condition<rule_processor::exact_match>(entry.id, condition);
            }
        } catch (const std::bad_cast&) {
            DDWAF_ERROR("Inconsistent data type for rule %s with ID %s",
                rule.name.c_str(), entry.id.c_str());
        }
    }
    return d;
}

}
