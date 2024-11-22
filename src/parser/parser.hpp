// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "builder/processor_builder.hpp"
#include "indexer.hpp"
#include "parameter.hpp"
#include "parser/common.hpp"
#include "parser/specification.hpp"
#include "rule.hpp"
#include "ruleset.hpp"
#include "ruleset_info.hpp"

namespace ddwaf::parser {

unsigned parse_schema_version(parameter::map &ruleset);
#ifdef LIBDDWAF_ENABLE_PARSER_V1
namespace v1 {
void parse(
    parameter::map &ruleset, base_ruleset_info &info, ddwaf::ruleset &rs, object_limits limits);
} // namespace v1
#endif
namespace v2 {

rule_spec_container parse_rules(parameter::vector &rule_array, base_section_info &info,
    std::unordered_map<std::string, std::string> &rule_data_ids, const object_limits &limits,
    core_rule::source_type source = core_rule::source_type::base);

matcher_container parse_data(parameter::vector &data_array,
    std::unordered_map<std::string, std::string> &data_ids_to_type, base_section_info &info);

override_spec_container parse_overrides(parameter::vector &override_array, base_section_info &info);

filter_spec_container parse_filters(parameter::vector &filter_array, base_section_info &info,
    std::unordered_map<std::string, std::string> &filter_data_ids, const object_limits &limits);

processor_container parse_processors(
    parameter::vector &processor_array, base_section_info &info, const object_limits &limits);

indexer<const scanner> parse_scanners(parameter::vector &scanner_array, base_section_info &info);

std::shared_ptr<action_mapper> parse_actions(
    parameter::vector &actions_array, base_section_info &info);

std::shared_ptr<expression> parse_expression(const parameter::vector &conditions_array,
    std::unordered_map<std::string, std::string> &data_ids_to_type, data_source source,
    const std::vector<transformer_id> &transformers, address_container &addresses,
    const object_limits &limits);

std::shared_ptr<expression> parse_simplified_expression(const parameter::vector &conditions_array,
    address_container &addresses, const object_limits &limits);

std::vector<transformer_id> parse_transformers(const parameter::vector &root, data_source &source);

// std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher(
// std::string_view name, const parameter::map &params);

} // namespace v2
} // namespace ddwaf::parser
