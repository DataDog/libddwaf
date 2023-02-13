// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/specification.hpp"
#include "test.h"

#define EXPECT_STR(a, b) EXPECT_STREQ(a.c_str(), b)
#define EXPECT_STRV(a, b) EXPECT_STREQ(a.data(), b)

/*TEST(TestParserV2, ParseRule)*/
/*{*/
/*ruleset_info info;*/
/*manifest manifest;*/
/*std::unordered_map<std::string, std::string> rule_data_ids;*/

/*auto rule_object = readRule(*/
/*R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator:
 * match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex,
 * parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex,
 * parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");*/

/*parameter::vector rule_array = parameter(rule_object);*/
/*auto rules = parser::v2::parse_rules(rule_array, info, manifest, rule_data_ids);*/
/*ddwaf_object_free(&rule_object);*/

/*EXPECT_EQ(rules.size(), 1);*/
/*EXPECT_NE(rules.find("1"), rules.end());*/

/*parser::rule_spec &rule = rules["1"];*/
/*EXPECT_TRUE(rule.enabled);*/
/*EXPECT_EQ(rule.conditions.size(), 3);*/
/*EXPECT_EQ(rule.actions.size(), 0);*/
/*EXPECT_STR(rule.name, "rule1");*/
/*EXPECT_EQ(rule.tags.size(), 2);*/
/*EXPECT_STR(rule.tags["type"], "flow1");*/
/*EXPECT_STR(rule.tags["category"], "category1");*/
/*}*/

/*TEST(TestParserV2, ParseRuleWithoutType)*/
/*{*/
/*ruleset_info info;*/
/*manifest manifest;*/
/*std::unordered_map<std::string, std::string> rule_data_ids;*/

/*auto rule_object = readRule(*/
/*R"([{id: 1, name: rule1, tags: {category: category1}, conditions: [{operator: match_regex,
 * parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs:
 * [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs:
 * [{address: arg2, key_path: [y]}], regex: .*}}]}])");*/

/*parameter::vector rule_array = parameter(rule_object);*/
/*auto rules = parser::v2::parse_rules(rule_array, info, manifest, rule_data_ids);*/
/*ddwaf_object_free(&rule_object);*/

/*EXPECT_EQ(rules.size(), 0);*/
/*}*/

/*TEST(TestParserV2, ParseRuleWithoutID)*/
/*{*/
/*ruleset_info info;*/
/*manifest manifest;*/
/*std::unordered_map<std::string, std::string> rule_data_ids;*/

/*auto rule_object = readRule(*/
/*R"([{name: rule1, tags: {type: type1, category: category1}, conditions: [{operator: match_regex,
 * parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs:
 * [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs:
 * [{address: arg2, key_path: [y]}], regex: .*}}]}])");*/

/*parameter::vector rule_array = parameter(rule_object);*/
/*auto rules = parser::v2::parse_rules(rule_array, info, manifest, rule_data_ids);*/
/*ddwaf_object_free(&rule_object);*/

/*EXPECT_EQ(rules.size(), 0);*/
/*}*/

/*TEST(TestParserV2, ParseMultipleRules)*/
/*{*/
/*ruleset_info info;*/
/*manifest manifest;*/

/*object_limits limits;*/

/*ddwaf::parser::V2::parser p(info, mb, dispatcher, limits);*/

/*auto rule_object = readRule(*/
/*R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator:
 * match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex,
 * parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex,
 * parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name:
 * rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator:
 * ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match:
 * [block]}])");*/

/*parameter::vector rule_array = parameter(rule_object);*/
/*EXPECT_EQ(rule_array.size(), 2);*/

/*auto rules = p.parse_rules(rule_array);*/
/*ddwaf_object_free(&rule_object);*/

/*EXPECT_EQ(rules.size(), 2);*/
/*EXPECT_NE(rules.find("1"), rules.end());*/
/*EXPECT_NE(rules.find("secondrule"), rules.end());*/

/*{*/
/*parser::rule_spec &rule = rules["1"];*/
/*EXPECT_TRUE(rule.enabled);*/
/*EXPECT_EQ(rule.conditions.size(), 3);*/
/*EXPECT_EQ(rule.actions.size(), 0);*/
/*EXPECT_STR(rule.name, "rule1");*/
/*EXPECT_EQ(rule.tags.size(), 2);*/
/*EXPECT_STR(rule.tags["type"], "flow1");*/
/*EXPECT_STR(rule.tags["category"], "category1");*/
/*}*/

/*{*/
/*parser::rule_spec &rule = rules["secondrule"];*/
/*EXPECT_TRUE(rule.enabled);*/
/*EXPECT_EQ(rule.conditions.size(), 1);*/
/*EXPECT_EQ(rule.actions.size(), 1);*/
/*EXPECT_STR(rule.actions[0], "block");*/
/*EXPECT_STR(rule.name, "rule2");*/
/*EXPECT_EQ(rule.tags.size(), 3);*/
/*EXPECT_STR(rule.tags["type"], "flow2");*/
/*EXPECT_STR(rule.tags["category"], "category2");*/
/*EXPECT_STR(rule.tags["confidence"], "none");*/
/*}*/
/*}*/

/*TEST(TestParserV2, ParseMultipleRulesOneInvalid)*/
/*{*/
/*ruleset_info info;*/
/*manifest manifest;*/

/*object_limits limits;*/

/*ddwaf::parser::V2::parser p(info, mb, dispatcher, limits);*/

/*auto rule_object = readRule(*/
/*R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator:
 * match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex,
 * parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex,
 * parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name:
 * rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator:
 * ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match:
 * [block]}, {id: error}])");*/

/*parameter::vector rule_array = parameter(rule_object);*/

/*auto rules = p.parse_rules(rule_array);*/
/*ddwaf_object_free(&rule_object);*/

/*EXPECT_EQ(rules.size(), 2);*/
/*EXPECT_NE(rules.find("1"), rules.end());*/
/*EXPECT_NE(rules.find("secondrule"), rules.end());*/

/*{*/
/*parser::rule_spec &rule = rules["1"];*/
/*EXPECT_TRUE(rule.enabled);*/
/*EXPECT_EQ(rule.conditions.size(), 3);*/
/*EXPECT_EQ(rule.actions.size(), 0);*/
/*EXPECT_STR(rule.name, "rule1");*/
/*EXPECT_EQ(rule.tags.size(), 2);*/
/*[>        EXPECT_STR(rule.tags["type"], "flow1");<]*/
/*[>EXPECT_STR(rule.tags["category"], "category1");<]*/
/*}*/

/*{*/
/*parser::rule_spec &rule = rules["secondrule"];*/
/*EXPECT_TRUE(rule.enabled);*/
/*EXPECT_EQ(rule.conditions.size(), 1);*/
/*EXPECT_EQ(rule.actions.size(), 1);*/
/*EXPECT_STR(rule.actions[0], "block");*/
/*EXPECT_STR(rule.name, "rule2");*/
/*EXPECT_EQ(rule.tags.size(), 3);*/
/*[>      EXPECT_STR(rule.tags["type"], "flow2");<]*/
/*[>EXPECT_STR(rule.tags["category"], "category2");<]*/
/*[>EXPECT_STR(rule.tags["confidence"], "none");<]*/
/*}*/
/*}*/

/*TEST(TestParserV2, ParseRuleOverride)*/
/*{*/
/*ruleset_info info;*/
/*manifest manifest;*/

/*object_limits limits;*/

/*ddwaf::parser::V2::parser p(info, mb, dispatcher, limits);*/

/*auto object = readRule(R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]}])");*/

/*parameter::vector override_array = parameter(object);*/
/*auto overrides = p.parse_overrides(override_array);*/
/*ddwaf_object_free(&object);*/

/*EXPECT_EQ(overrides.by_ids.size(), 0);*/
/*EXPECT_EQ(overrides.by_tags.size(), 1);*/

/*auto &ovrd = overrides.by_tags[0];*/
/*EXPECT_FALSE(ovrd.enabled.has_value());*/
/*EXPECT_TRUE(ovrd.actions.has_value());*/
/*EXPECT_EQ(ovrd.actions->size(), 1);*/
/*EXPECT_STR((*ovrd.actions)[0], "block");*/
/*EXPECT_EQ(ovrd.targets.size(), 1);*/

/*auto &target = ovrd.targets[0];*/
/*EXPECT_EQ(target.type, parser::target_type::tags);*/
/*EXPECT_TRUE(target.rule_id.empty());*/
/*EXPECT_EQ(target.tags.size(), 1);*/
/*// EXPECT_STR(target.tags["confidence"], "1");*/
/*}*/

/*TEST(TestParserV2, ParseMultipleRuleOverrides)*/
/*{*/
/*ruleset_info info;*/
/*manifest manifest;*/

/*object_limits limits;*/

/*ddwaf::parser::V2::parser p(info, mb, dispatcher, limits);*/

/*auto object = readRule(*/
/*R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]},{rules_target: [{rule_id: 1}],
 * enabled: false}])");*/

/*parameter::vector override_array = parameter(object);*/
/*auto overrides = p.parse_overrides(override_array);*/
/*ddwaf_object_free(&object);*/

/*EXPECT_EQ(overrides.by_ids.size(), 1);*/
/*EXPECT_EQ(overrides.by_tags.size(), 1);*/

/*{*/
/*auto &ovrd = overrides.by_tags[0];*/
/*EXPECT_FALSE(ovrd.enabled.has_value());*/
/*EXPECT_TRUE(ovrd.actions.has_value());*/
/*EXPECT_EQ(ovrd.actions->size(), 1);*/
/*EXPECT_STR((*ovrd.actions)[0], "block");*/
/*EXPECT_EQ(ovrd.targets.size(), 1);*/

/*auto &target = ovrd.targets[0];*/
/*EXPECT_EQ(target.type, parser::target_type::tags);*/
/*EXPECT_TRUE(target.rule_id.empty());*/
/*EXPECT_EQ(target.tags.size(), 1);*/
/*// EXPECT_EQ(target.tags[0], {"confidence","1"});*/
/*}*/

/*{*/
/*auto &ovrd = overrides.by_ids[0];*/
/*EXPECT_TRUE(ovrd.enabled.has_value());*/
/*EXPECT_FALSE(*ovrd.enabled);*/
/*EXPECT_FALSE(ovrd.actions.has_value());*/
/*EXPECT_EQ(ovrd.targets.size(), 1);*/

/*auto &target = ovrd.targets[0];*/
/*EXPECT_EQ(target.type, parser::target_type::id);*/
/*EXPECT_STR(target.rule_id, "1");*/
/*EXPECT_EQ(target.tags.size(), 0);*/
/*}*/
/*}*/

/*TEST(TestParserV2, ParseInconsistentRuleOverride)*/
/*{*/
/*ruleset_info info;*/
/*manifest manifest;*/

/*object_limits limits;*/

/*ddwaf::parser::V2::parser p(info, mb, dispatcher, limits);*/

/*auto object = readRule(*/
/*R"([{rules_target: [{tags: {confidence: 1}}, {rule_id: 1}], on_match: [block], enabled:
 * false}])");*/

/*parameter::vector override_array = parameter(object);*/
/*auto overrides = p.parse_overrides(override_array);*/
/*ddwaf_object_free(&object);*/

/*EXPECT_EQ(overrides.by_ids.size(), 0);*/
/*EXPECT_EQ(overrides.by_tags.size(), 0);*/
/*}*/
