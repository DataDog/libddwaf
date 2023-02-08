// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <manifest.hpp>
#include <parameter.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace ddwaf::parser {

void parse(parameter object, ruleset_info &info, ddwaf::ruleset &rs, object_limits limits);

unsigned parse_schema_version(parameter::map &ruleset);

namespace v1 {
void parse(parameter::map &ruleset, ruleset_info &info, ddwaf::ruleset &rs, object_limits limits);
} // namespace v1

namespace v2 {
void parse(parameter::map &ruleset, ruleset_info &info, ddwaf::ruleset &rs, object_limits limits);

std::unordered_map<std::string_view, rule::ptr> parse_rules(
    ddwaf::parameter::vector &rules_array, ddwaf::ruleset_info &info,
    manifest_builder &mb, rule_data::dispatcher &dispatcher, object_limits limits);

} // namespace v2

} // namespace ddwaf::parser
