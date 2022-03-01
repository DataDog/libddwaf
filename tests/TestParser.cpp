// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

void run_test(ddwaf_handle handle)
{
    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
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
    EXPECT_EQ(code, DDWAF_MONITOR);
    EXPECT_FALSE(ret.timeout);
    EXPECT_STREQ(ret.data, R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"flow1","category":"category1"}},"rule_matches":[{"operator":"match_regex","operator_value":".*","parameters":[{"address":"arg1","key_path":[],"value":"string 1","highlight":["string 1"]}]},{"operator":"match_regex","operator_value":".*","parameters":[{"address":"arg2","key_path":["x"],"value":"string 2","highlight":["string 2"]}]},{"operator":"match_regex","operator_value":".*","parameters":[{"address":"arg2","key_path":["y"],"value":"string 3","highlight":["string 3"]}]}]}])");
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
}

TEST(TestParserV1, Basic)
{
    auto rule = readRule(R"({version: '1.1', events: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operation: match_regex, parameters: {inputs: [arg1], regex: .*}}, {operation: match_regex, parameters: {inputs: [arg2:x], regex: .*}},{operation: match_regex, parameters: {inputs: [arg2:y], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    run_test(handle);

    ddwaf_destroy(handle);
}

TEST(TestParserV2, Basic)
{
    auto rule = readRule(R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    run_test(handle);

    ddwaf_destroy(handle);
}

TEST(TestParserV1, TestInvalidRule)
{
    auto rule = readRule(R"({version: '1.1', events: [{id: 1, name: rule1, tags: {category: category1}, conditions: [{operation: match_regex, parameters: {inputs: [arg1], regex: .*}}, {operation: match_regex, parameters: {inputs: [arg2:x], regex: .*}},{operation: match_regex, parameters: {inputs: [arg2:y], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter::map errors = parameter(info.errors);
    EXPECT_EQ(errors.size(), 1);

    ddwaf::parameter::vector rules = errors.begin()->second;
    EXPECT_EQ(rules.size(), 1);
    EXPECT_STREQ(std::string(rules[0]).c_str(), "1");

    EXPECT_EQ(info.failed, 1);
    EXPECT_EQ(info.loaded, 0);

    ddwaf_ruleset_info_free(&info);

    ddwaf_destroy(handle);
}

TEST(TestParserV1, TestMultipleInvalidRules)
{
    auto rule = readRule(R"({version: '1.1', events: [{id: 1, name: rule1, tags: {category: category1}, conditions: [{operation: match_regex, parameters: {inputs: [arg1], regex: .*}}, {operation: match_regex, parameters: {inputs: [arg2:x], regex: .*}},{operation: match_regex, parameters: {inputs: [arg2:y], regex: .*}}]},{id: 2, name: rule2, tags: {type: flow1, category: category1}, conditions: [{operation: squash, parameters: {inputs: [arg1], regex: .*}}, {operation: match_regex, parameters: {inputs: [arg2:x], regex: .*}},{operation: match_regex, parameters: {inputs: [arg2:y], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter::map errors = parameter(info.errors);
    EXPECT_EQ(errors.size(), 2);

    EXPECT_EQ(info.failed, 2);
    EXPECT_EQ(info.loaded, 0);

    ddwaf_ruleset_info_free(&info);

    ddwaf_destroy(handle);
}
