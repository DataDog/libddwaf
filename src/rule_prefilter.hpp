// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <clock.hpp>
#include <exception.hpp>
#include <exclusion_filter.hpp>
#include <object_store.hpp>
#include <rule.hpp>
#include <ruleset.hpp>

// Using a bunch of exclusion filters, the rule prefilter provides the
// context with a list of rules to run on.

// FIXME: rule_ref_vector should hold const references
namespace ddwaf {

class rule_prefilter {
public:
    // TODO: construct with filters
    explicit rule_prefilter(ddwaf::ruleset &ruleset): ruleset_(ruleset) {}

    // TODO pass object_store
    rule_ref_vector filter(ddwaf::object_store & /*store*/, ddwaf::timer&  /*deadline*/)
    {
        ddwaf::rule_ref_vector rules_to_run;
        for (auto &rule : ruleset_.rules) {
            rules_to_run.push_back(rule);
        }
        return rules_to_run;
    }

protected:
    ddwaf::ruleset &ruleset_;
};

} // namespace ddwaf
