// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestParserV2Rules, ParseRule)
{
    ruleset_info info;
    ddwaf::manifest manifest;
    std::unordered_map<std::string, std::string> rule_data_ids;

    auto rule_object = readRule(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    parameter::vector rule_array = parameter(rule_object);
    auto rules = parser::v2::parse_rules(rule_array, info, manifest, rule_data_ids);
    ddwaf_object_free(&rule_object);

    EXPECT_EQ(rules.size(), 1);
    EXPECT_NE(rules.find("1"), rules.end());

    parser::rule_spec &rule = rules["1"];
    EXPECT_TRUE(rule.enabled);
    EXPECT_EQ(rule.conditions.size(), 3);
    EXPECT_EQ(rule.actions.size(), 0);
    EXPECT_STR(rule.name, "rule1");
    EXPECT_EQ(rule.tags.size(), 2);
    EXPECT_STR(rule.tags["type"], "flow1");
    EXPECT_STR(rule.tags["category"], "category1");
}

TEST(TestParserV2Rules, ParseRuleWithoutType)
{
    ruleset_info info;
    ddwaf::manifest manifest;
    std::unordered_map<std::string, std::string> rule_data_ids;

    auto rule_object = readRule(
        R"([{id: 1, name: rule1, tags: {category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    parameter::vector rule_array = parameter(rule_object);
    auto rules = parser::v2::parse_rules(rule_array, info, manifest, rule_data_ids);
    ddwaf_object_free(&rule_object);

    EXPECT_EQ(rules.size(), 0);
}

TEST(TestParserV2Rules, ParseRuleWithoutID)
{
    ruleset_info info;
    ddwaf::manifest manifest;
    std::unordered_map<std::string, std::string> rule_data_ids;

    auto rule_object = readRule(
        R"([{name: rule1, tags: {type: type1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    parameter::vector rule_array = parameter(rule_object);
    auto rules = parser::v2::parse_rules(rule_array, info, manifest, rule_data_ids);
    ddwaf_object_free(&rule_object);

    EXPECT_EQ(rules.size(), 0);
}

TEST(TestParserV2Rules, ParseMultipleRules)
{
    ruleset_info info;
    ddwaf::manifest manifest;
    std::unordered_map<std::string, std::string> rule_data_ids;

    auto rule_object = readRule(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}])");

    parameter::vector rule_array = parameter(rule_object);
    EXPECT_EQ(rule_array.size(), 2);

    auto rules = parser::v2::parse_rules(rule_array, info, manifest, rule_data_ids);
    ddwaf_object_free(&rule_object);

    EXPECT_EQ(rules.size(), 2);
    EXPECT_NE(rules.find("1"), rules.end());
    EXPECT_NE(rules.find("secondrule"), rules.end());

    {
        parser::rule_spec &rule = rules["1"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.conditions.size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags["type"], "flow1");
        EXPECT_STR(rule.tags["category"], "category1");
    }

    {
        parser::rule_spec &rule = rules["secondrule"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.conditions.size(), 1);
        EXPECT_EQ(rule.actions.size(), 1);
        EXPECT_STR(rule.actions[0], "block");
        EXPECT_STR(rule.name, "rule2");
        EXPECT_EQ(rule.tags.size(), 3);
        EXPECT_STR(rule.tags["type"], "flow2");
        EXPECT_STR(rule.tags["category"], "category2");
        EXPECT_STR(rule.tags["confidence"], "none");
    }
}

TEST(TestParserV2Rules, ParseMultipleRulesOneInvalid)
{
    ruleset_info info;
    ddwaf::manifest manifest;
    std::unordered_map<std::string, std::string> rule_data_ids;

    auto rule_object = readRule(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}, {id: error}])");

    parameter::vector rule_array = parameter(rule_object);

    auto rules = parser::v2::parse_rules(rule_array, info, manifest, rule_data_ids);
    ddwaf_object_free(&rule_object);

    EXPECT_EQ(rules.size(), 2);
    EXPECT_NE(rules.find("1"), rules.end());
    EXPECT_NE(rules.find("secondrule"), rules.end());

    {
        parser::rule_spec &rule = rules["1"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.conditions.size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags["type"], "flow1");
        EXPECT_STR(rule.tags["category"], "category1");
    }

    {
        parser::rule_spec &rule = rules["secondrule"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.conditions.size(), 1);
        EXPECT_EQ(rule.actions.size(), 1);
        EXPECT_STR(rule.actions[0], "block");
        EXPECT_STR(rule.name, "rule2");
        EXPECT_EQ(rule.tags.size(), 3);
        EXPECT_STR(rule.tags["type"], "flow2");
        EXPECT_STR(rule.tags["category"], "category2");
        EXPECT_STR(rule.tags["confidence"], "none");
    }
}

TEST(TestParserV2Rules, ParseMultipleRulesOneDuplicate)
{
    ruleset_info info;
    ddwaf::manifest manifest;
    std::unordered_map<std::string, std::string> rule_data_ids;

    auto rule_object = readRule(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: 1, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}])");

    parameter::vector rule_array = parameter(rule_object);
    EXPECT_EQ(rule_array.size(), 2);

    auto rules = parser::v2::parse_rules(rule_array, info, manifest, rule_data_ids);
    ddwaf_object_free(&rule_object);

    EXPECT_EQ(rules.size(), 1);
    EXPECT_NE(rules.find("1"), rules.end());

    {
        parser::rule_spec &rule = rules["1"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.conditions.size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags["type"], "flow1");
        EXPECT_STR(rule.tags["category"], "category1");
    }
}
