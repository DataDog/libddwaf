// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "indexer.hpp"
#include "object_view.hpp"
#include "parser/specification.hpp"
#include "rule.hpp"
#include "ruleset.hpp"
#include "ruleset_info.hpp"

using base_section_info = ddwaf::base_ruleset_info::base_section_info;

namespace ddwaf::parser {

unsigned parse_schema_version(const std::unordered_map<std::string_view, object_view> &ruleset);

namespace v2 {

rule_spec_container parse_rules(object_view::array &rule_array, base_section_info &info,
    std::unordered_map<std::string, std::string> &rule_data_ids, const object_limits &limits,
    rule::source_type source = rule::source_type::base);

rule_data_container parse_rule_data(object_view::array &rule_data, base_section_info &info,
    std::unordered_map<std::string, std::string> &rule_data_ids);

override_spec_container parse_overrides(
    object_view::array &override_array, base_section_info &info);

filter_spec_container parse_filters(
    object_view::array &filter_array, base_section_info &info, const object_limits &limits);

processor_container parse_processors(
    object_view::array &processor_array, base_section_info &info, const object_limits &limits);

indexer<const scanner> parse_scanners(object_view::array &scanner_array, base_section_info &info);

std::shared_ptr<action_mapper> parse_actions(
    object_view::array &actions_array, base_section_info &info);

} // namespace v2
} // namespace ddwaf::parser
