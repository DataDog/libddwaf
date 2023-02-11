// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "parser/specification.hpp"
#include <manifest.hpp>
#include <parameter.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace ddwaf::parser {

unsigned parse_schema_version(parameter::map &ruleset);

namespace v1 {
void parse(parameter::map &ruleset, ruleset_info &info, ddwaf::ruleset &rs, object_limits limits);
} // namespace v1

namespace v2 {
class parser {
public:
    parser(ddwaf::ruleset_info &info, manifest &target_manifest,
        rule_data::dispatcher &dispatcher, object_limits limits)
        : info_(info), target_manifest_(target_manifest),
        dispatcher_(dispatcher), limits_(limits){}

    rule_spec_container parse_rules(parameter::vector &rule_array);
    override_spec_container parse_overrides(parameter::vector &override_array);
    filter_spec_container parse_filters(parameter::vector &filter_array);

protected:
    condition::ptr parse_condition(parameter::map &root,
        condition::data_source source = condition::data_source::values,
        std::vector<PW_TRANSFORM_ID> transformers = {});

    rule_spec parse_rule(parameter::map &rule);

    std::pair<override_spec, target_type> parse_override(parameter::map &node);

    input_filter_spec parse_input_filter(parameter::map &filter);
    rule_filter_spec parse_rule_filter(parameter::map &filter);

    ddwaf::ruleset_info &info_;
    manifest &target_manifest_;
    rule_data::dispatcher &dispatcher_;
    object_limits limits_;
};

} // namespace v2
} // namespace ddwaf::parser
