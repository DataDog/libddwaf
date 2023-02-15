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
rule_spec_container parse_rules(parameter::vector &rule_array, ddwaf::ruleset_info &info,
    manifest &target_manifest, std::unordered_map<std::string, std::string> &rule_data_ids,
    const object_limits &limits);

rule_data_container parse_rule_data(
    parameter::vector &rule_data, std::unordered_map<std::string, std::string> &rule_data_ids);

override_spec_container parse_overrides(parameter::vector &override_array);

filter_spec_container parse_filters(
    parameter::vector &filter_array, manifest &target_manifest, const object_limits &limits);

} // namespace v2
} // namespace ddwaf::parser
