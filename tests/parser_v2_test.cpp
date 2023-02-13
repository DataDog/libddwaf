// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

static void run_test(ddwaf_handle handle)
{
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param, arg2, tmp;
    ddwaf_object_map(&param);
    ddwaf_object_map(&arg2);

    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "string 1"));
    ddwaf_object_map_add(&arg2, "x", ddwaf_object_string(&tmp, "string 2"));
    ddwaf_object_map_add(&arg2, "y", ddwaf_object_string(&tmp, "string 3"));
    ddwaf_object_map_add(&param, "arg2", &arg2);

    ddwaf_result ret;

    // Run with just arg1
    auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MATCH);
    EXPECT_FALSE(ret.timeout);
    EXPECT_STREQ(ret.data,
        R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"flow1","category":"category1"}},"rule_matches":[{"operator":"match_regex","operator_value":".*","parameters":[{"address":"arg1","key_path":[],"value":"string 1","highlight":["string 1"]}]},{"operator":"match_regex","operator_value":".*","parameters":[{"address":"arg2","key_path":["x"],"value":"string 2","highlight":["string 2"]}]},{"operator":"match_regex","operator_value":".*","parameters":[{"address":"arg2","key_path":["y"],"value":"string 3","highlight":["string 3"]}]}]}])");
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
}

TEST(TestParserV2, Basic)
{
    auto rule = readRule(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    EXPECT_EQ(info.loaded, 1);
    EXPECT_EQ(info.failed, 0);
    EXPECT_STREQ(info.version, "1.2.7");
    ddwaf::parameter::map errors = parameter(info.errors);
    EXPECT_EQ(errors.size(), 0);
    ddwaf_ruleset_info_free(&info);

    run_test(handle);

    ddwaf_destroy(handle);
}

TEST(TestParserV2, TestInvalidRule)
{
    auto rule = readFile("invalid_single.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter::map errors = parameter(info.errors);
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    ddwaf::parameter::string_set rules = it->second;
    EXPECT_EQ(rules.size(), 1);
    EXPECT_NE(rules.find("1"), rules.end());

    EXPECT_EQ(info.failed, 1);
    EXPECT_EQ(info.loaded, 0);

    ddwaf_ruleset_info_free(&info);
}

TEST(TestParserV2, TestMultipleSameInvalidRules)
{
    auto rule = readFile("invalid_multiple_same.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter::map errors = parameter(info.errors);
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    ddwaf::parameter::string_set rules = it->second;
    EXPECT_EQ(rules.size(), 2);
    EXPECT_NE(rules.find("1"), rules.end());
    EXPECT_NE(rules.find("2"), rules.end());

    EXPECT_EQ(info.failed, 2);
    EXPECT_EQ(info.loaded, 0);

    ddwaf_ruleset_info_free(&info);
}

TEST(TestParserV2, TestMultipleDiffInvalidRules)
{
    auto rule = readFile("invalid_multiple_diff.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter::map errors = parameter(info.errors);
    EXPECT_EQ(errors.size(), 2);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        ddwaf::parameter::string_set rules = it->second;
        EXPECT_EQ(rules.size(), 1);
        EXPECT_NE(rules.find("1"), rules.end());
    }

    {
        auto it = errors.find("unknown processor: squash");
        EXPECT_NE(it, errors.end());

        ddwaf::parameter::string_set rules = it->second;
        EXPECT_EQ(rules.size(), 1);
        EXPECT_NE(rules.find("2"), rules.end());
    }

    EXPECT_EQ(info.failed, 2);
    EXPECT_EQ(info.loaded, 0);

    ddwaf_ruleset_info_free(&info);
}

TEST(TestParserV2, TestMultipleMixInvalidRules)
{
    auto rule = readFile("invalid_multiple_mix.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter::map errors = parameter(info.errors);
    EXPECT_EQ(errors.size(), 3);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        ddwaf::parameter::string_set rules = it->second;
        EXPECT_EQ(rules.size(), 2);
        EXPECT_NE(rules.find("1"), rules.end());
        EXPECT_NE(rules.find("3"), rules.end());
    }

    {
        auto it = errors.find("unknown processor: squash");
        EXPECT_NE(it, errors.end());

        ddwaf::parameter::string_set rules = it->second;
        EXPECT_EQ(rules.size(), 1);
        EXPECT_NE(rules.find("2"), rules.end());
    }

    {
        auto it = errors.find("missing key 'inputs'");
        EXPECT_NE(it, errors.end());

        ddwaf::parameter::string_set rules = it->second;
        EXPECT_EQ(rules.size(), 1);
        EXPECT_NE(rules.find("4"), rules.end());
    }

    EXPECT_EQ(info.failed, 4);
    EXPECT_EQ(info.loaded, 1);

    ddwaf_ruleset_info_free(&info);

    ddwaf_destroy(handle);
}

TEST(TestParserV2, TestInvalidDuplicate)
{
    auto rule = readFile("invalid_duplicate.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter::map errors = parameter(info.errors);
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("duplicate rule");
    EXPECT_NE(it, errors.end());

    ddwaf::parameter::string_set rules = it->second;
    EXPECT_EQ(rules.size(), 1);
    EXPECT_NE(rules.find("1"), rules.end());

    EXPECT_EQ(info.failed, 1);
    EXPECT_EQ(info.loaded, 1);

    ddwaf_ruleset_info_free(&info);

    ddwaf_destroy(handle);
}

TEST(TestParserV2, TestInvalidRuleset)
{
    auto rule = readFile("invalid_ruleset.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter::map errors = parameter(info.errors);
    EXPECT_EQ(errors.size(), 20);

    EXPECT_EQ(info.failed, 400);
    EXPECT_EQ(info.loaded, 0);

    for (auto &[key, value] : errors) {
        ddwaf::parameter::vector rules = parameter(value);
        EXPECT_EQ(rules.size(), 20);
    }
    ddwaf_ruleset_info_free(&info);

    ddwaf_destroy(handle);
}

TEST(TestParserV2, ParseRule)
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

TEST(TestParserV2, ParseRuleWithoutType)
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

TEST(TestParserV2, ParseRuleWithoutID)
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

TEST(TestParserV2, ParseMultipleRules)
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

TEST(TestParserV2, ParseMultipleRulesOneInvalid)
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
        /*        EXPECT_STR(rule.tags["type"], "flow1");*/
        /*EXPECT_STR(rule.tags["category"], "category1");*/
    }

    {
        parser::rule_spec &rule = rules["secondrule"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.conditions.size(), 1);
        EXPECT_EQ(rule.actions.size(), 1);
        EXPECT_STR(rule.actions[0], "block");
        EXPECT_STR(rule.name, "rule2");
        EXPECT_EQ(rule.tags.size(), 3);
        /*      EXPECT_STR(rule.tags["type"], "flow2");*/
        /*EXPECT_STR(rule.tags["category"], "category2");*/
        /*EXPECT_STR(rule.tags["confidence"], "none");*/
    }
}

TEST(TestParserV2, ParseRuleOverride)
{
    auto object = readRule(R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]}])");

    parameter::vector override_array = parameter(object);
    auto overrides = parser::v2::parse_overrides(override_array);
    ddwaf_object_free(&object);

    EXPECT_EQ(overrides.by_ids.size(), 0);
    EXPECT_EQ(overrides.by_tags.size(), 1);

    auto &ovrd = overrides.by_tags[0];
    EXPECT_FALSE(ovrd.enabled.has_value());
    EXPECT_TRUE(ovrd.actions.has_value());
    EXPECT_EQ(ovrd.actions->size(), 1);
    EXPECT_STR((*ovrd.actions)[0], "block");
    EXPECT_EQ(ovrd.targets.size(), 1);

    auto &target = ovrd.targets[0];
    EXPECT_EQ(target.type, parser::target_type::tags);
    EXPECT_TRUE(target.rule_id.empty());
    EXPECT_EQ(target.tags.size(), 1);
    // EXPECT_STR(target.tags["confidence"], "1");
}

TEST(TestParserV2, ParseMultipleRuleOverrides)
{
    auto object = readRule(
        R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]},{rules_target: [{rule_id: 1}], enabled: false}])");

    parameter::vector override_array = parameter(object);
    auto overrides = parser::v2::parse_overrides(override_array);
    ddwaf_object_free(&object);

    EXPECT_EQ(overrides.by_ids.size(), 1);
    EXPECT_EQ(overrides.by_tags.size(), 1);

    {
        auto &ovrd = overrides.by_tags[0];
        EXPECT_FALSE(ovrd.enabled.has_value());
        EXPECT_TRUE(ovrd.actions.has_value());
        EXPECT_EQ(ovrd.actions->size(), 1);
        EXPECT_STR((*ovrd.actions)[0], "block");
        EXPECT_EQ(ovrd.targets.size(), 1);

        auto &target = ovrd.targets[0];
        EXPECT_EQ(target.type, parser::target_type::tags);
        EXPECT_TRUE(target.rule_id.empty());
        EXPECT_EQ(target.tags.size(), 1);
        // EXPECT_EQ(target.tags[0], {"confidence","1"});
    }

    {
        auto &ovrd = overrides.by_ids[0];
        EXPECT_TRUE(ovrd.enabled.has_value());
        EXPECT_FALSE(*ovrd.enabled);
        EXPECT_FALSE(ovrd.actions.has_value());
        EXPECT_EQ(ovrd.targets.size(), 1);

        auto &target = ovrd.targets[0];
        EXPECT_EQ(target.type, parser::target_type::id);
        EXPECT_STR(target.rule_id, "1");
        EXPECT_EQ(target.tags.size(), 0);
    }
}

TEST(TestParserV2, ParseInconsistentRuleOverride)
{
    auto object = readRule(
        R"([{rules_target: [{tags: {confidence: 1}}, {rule_id: 1}], on_match: [block], enabled: false}])");

    parameter::vector override_array = parameter(object);
    auto overrides = parser::v2::parse_overrides(override_array);
    ddwaf_object_free(&object);

    EXPECT_EQ(overrides.by_ids.size(), 0);
    EXPECT_EQ(overrides.by_tags.size(), 0);
}
