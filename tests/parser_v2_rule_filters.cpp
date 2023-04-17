// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ruleset_info.hpp"
#include "test.h"

TEST(TestParserV2RuleFilters, ParseEmptyFilter)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(R"([{id: 1}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 0);
}

TEST(TestParserV2RuleFilters, ParseFilterWithoutID)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(R"([{rules_target: [{rule_id: 2939}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 0);
}

TEST(TestParserV2RuleFilters, ParseDuplicateUnconditional)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(
        R"([{id: 1, rules_target: [{rule_id: 2939}]},{id: 1, rules_target: [{tags: {type: rule, category: unknown}}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 1);
    EXPECT_EQ(filters.input_filters.size(), 0);
}

TEST(TestParserV2RuleFilters, ParseUnconditionalTargetID)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(R"([{id: 1, rules_target: [{rule_id: 2939}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 1);
    EXPECT_EQ(filters.input_filters.size(), 0);

    const auto &filter_it = filters.rule_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 0);
    EXPECT_EQ(filter.targets.size(), 1);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::id);
    EXPECT_STR(target.rule_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestParserV2RuleFilters, ParseUnconditionalTargetTags)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(R"([{id: 1, rules_target: [{tags: {type: rule, category: unknown}}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 1);
    EXPECT_EQ(filters.input_filters.size(), 0);

    const auto &filter_it = filters.rule_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 0);
    EXPECT_EQ(filter.targets.size(), 1);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::tags);
    EXPECT_TRUE(target.rule_id.empty());
    EXPECT_EQ(target.tags.size(), 2);
    EXPECT_STR(target.tags.find("type")->second, "rule");
    EXPECT_STR(target.tags.find("category")->second, "unknown");
}

TEST(TestParserV2RuleFilters, ParseUnconditionalTargetPriority)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(
        R"([{id: 1, rules_target: [{rule_id: 2939, tags: {type: rule, category: unknown}}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 1);
    EXPECT_EQ(filters.input_filters.size(), 0);

    const auto &filter_it = filters.rule_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 0);
    EXPECT_EQ(filter.targets.size(), 1);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::id);
    EXPECT_STR(target.rule_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestParserV2RuleFilters, ParseUnconditionalMultipleTargets)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(
        R"([{id: 1, rules_target: [{rule_id: 2939},{tags: {type: rule, category: unknown}}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 1);
    EXPECT_EQ(filters.input_filters.size(), 0);

    const auto &filter_it = filters.rule_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 0);
    EXPECT_EQ(filter.targets.size(), 2);

    {
        const auto &target = filter.targets[0];
        EXPECT_EQ(target.type, parser::target_type::id);
        EXPECT_STR(target.rule_id, "2939");
        EXPECT_EQ(target.tags.size(), 0);
    }

    {
        const auto &target = filter.targets[1];
        EXPECT_EQ(target.type, parser::target_type::tags);
        EXPECT_TRUE(target.rule_id.empty());
        EXPECT_EQ(target.tags.size(), 2);
        EXPECT_STR(target.tags.find("type")->second, "rule");
        EXPECT_STR(target.tags.find("category")->second, "unknown");
    }
}

TEST(TestParserV2RuleFilters, ParseMultipleUnconditional)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(
        R"([{id: 1, rules_target: [{rule_id: 2939}]},{id: 2, rules_target: [{tags: {type: rule, category: unknown}}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 2);
    EXPECT_EQ(filters.input_filters.size(), 0);

    {
        const auto &filter_it = filters.rule_filters.find("1");
        EXPECT_STR(filter_it->first, "1");

        const auto &filter = filter_it->second;
        EXPECT_EQ(filter.conditions.size(), 0);
        EXPECT_EQ(filter.targets.size(), 1);

        const auto &target = filter.targets[0];
        EXPECT_EQ(target.type, parser::target_type::id);
        EXPECT_STR(target.rule_id, "2939");
        EXPECT_EQ(target.tags.size(), 0);
    }

    {
        const auto &filter_it = filters.rule_filters.find("2");
        EXPECT_STR(filter_it->first, "2");

        const auto &filter = filter_it->second;
        EXPECT_EQ(filter.conditions.size(), 0);
        EXPECT_EQ(filter.targets.size(), 1);

        const auto &target = filter.targets[0];
        EXPECT_EQ(target.type, parser::target_type::tags);
        EXPECT_TRUE(target.rule_id.empty());
        EXPECT_EQ(target.tags.size(), 2);
        EXPECT_STR(target.tags.find("type")->second, "rule");
        EXPECT_STR(target.tags.find("category")->second, "unknown");
    }
}

TEST(TestParserV2RuleFilters, ParseDuplicateConditional)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(
        R"([{id: 1, rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]},{id: 1, rules_target: [{tags: {type: rule, category: unknown}}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 1);
    EXPECT_EQ(filters.input_filters.size(), 0);
}

TEST(TestParserV2RuleFilters, ParseConditionalSingleCondition)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(
        R"([{id: 1, rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 1);
    EXPECT_EQ(filters.input_filters.size(), 0);

    const auto &filter_it = filters.rule_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 1);
    EXPECT_EQ(filter.targets.size(), 1);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::id);
    EXPECT_STR(target.rule_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestParserV2RuleFilters, ParseConditionalGlobal)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(
        R"([{id: 1, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 1);
    EXPECT_EQ(filters.input_filters.size(), 0);

    const auto &filter_it = filters.rule_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 1);
    EXPECT_EQ(filter.targets.size(), 0);
}

TEST(TestParserV2RuleFilters, ParseConditionalMultipleConditions)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(
        R"([{id: 1, rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 1);
    EXPECT_EQ(filters.input_filters.size(), 0);

    const auto &filter_it = filters.rule_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 3);
    EXPECT_EQ(filter.targets.size(), 1);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::id);
    EXPECT_STR(target.rule_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}
