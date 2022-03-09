// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <clock.hpp>
#include <ddwaf.h>
#include <rule.hpp>

namespace ddwaf
{

class metrics_collector
{
public:
    metrics_collector(const rule_vector& rules) : rules_(rules), rule_runtime_(rules.size(), 0) {}

    void record_rule(const rule::index_type index,
                     ddwaf::monotonic_clock::duration duration)
    {
        rule_runtime_[index] += duration.count();
    }

    void record_total(ddwaf::monotonic_clock::duration duration)
    {
        total_runtime_ += duration.count();
    }

    ddwaf_metrics generate_metrics();

protected:
    const rule_vector& rules_;

    uint64_t total_runtime_ { 0 };
    // Assume rules are always consecutive
    std::vector<uint64_t> rule_runtime_;
};

}
