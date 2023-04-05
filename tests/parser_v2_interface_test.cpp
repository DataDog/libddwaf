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
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                                           .op_value = ".*",
                                           .address = "arg1",
                                           .value = "string 1",
                                           .highlight = "string 1"},
                               {.op = "match_regex",
                                   .op_value = ".*",
                                   .address = "arg2",
                                   .path = {"x"},
                                   .value = "string 2",
                                   .highlight = "string 2"},
                               {.op = "match_regex",
                                   .op_value = ".*",
                                   .address = "arg2",
                                   .path = {"y"},
                                   .value = "string 3",
                                   .highlight = "string 3"}}});
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
}

TEST(TestParserV2Interface, Basic)
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
    auto errors = static_cast<ddwaf::parameter::map>(parameter(info.errors));
    EXPECT_EQ(errors.size(), 0);
    ddwaf_ruleset_info_free(&info);

    run_test(handle);

    ddwaf_destroy(handle);
}

TEST(TestParserV2Interface, BasicWithUpdate)
{
    auto rule = readRule(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_NE(handle, nullptr);

    EXPECT_EQ(info.loaded, 1);
    EXPECT_EQ(info.failed, 0);
    EXPECT_STREQ(info.version, "1.2.7");
    auto errors = static_cast<ddwaf::parameter::map>(parameter(info.errors));
    EXPECT_EQ(errors.size(), 0);
    ddwaf_ruleset_info_free(&info);

    info.loaded = 4;
    info.failed = 3;

    ddwaf_handle new_handle = ddwaf_update(handle, &rule, &info);
    ASSERT_NE(handle, nullptr);

    EXPECT_EQ(info.loaded, 1);
    EXPECT_EQ(info.failed, 0);
    EXPECT_STREQ(info.version, "1.2.7");
    errors = static_cast<ddwaf::parameter::map>(parameter(info.errors));
    EXPECT_EQ(errors.size(), 0);
    ddwaf_ruleset_info_free(&info);

    ddwaf_object_free(&rule);
    run_test(new_handle);

    ddwaf_destroy(handle);
    ddwaf_destroy(new_handle);
}

TEST(TestParserV2Interface, NullRuleset)
{
    ddwaf_ruleset_info info;
    info.loaded = 1;
    info.failed = 2;

    ddwaf_handle handle = ddwaf_init(nullptr, nullptr, &info);
    ASSERT_EQ(handle, nullptr);

    EXPECT_EQ(info.loaded, 0);
    EXPECT_EQ(info.failed, 0);
}

TEST(TestParserV2Interface, TestInvalidRule)
{
    auto rule = readFile("invalid_single.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    auto errors = static_cast<ddwaf::parameter::map>(parameter(info.errors));
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(rules.size(), 1);
    EXPECT_NE(rules.find("1"), rules.end());

    EXPECT_EQ(info.failed, 1);
    EXPECT_EQ(info.loaded, 0);

    ddwaf_ruleset_info_free(&info);
}

TEST(TestParserV2Interface, TestMultipleSameInvalidRules)
{
    auto rule = readFile("invalid_multiple_same.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    auto errors = static_cast<ddwaf::parameter::map>(parameter(info.errors));
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(rules.size(), 2);
    EXPECT_NE(rules.find("1"), rules.end());
    EXPECT_NE(rules.find("2"), rules.end());

    EXPECT_EQ(info.failed, 2);
    EXPECT_EQ(info.loaded, 0);

    ddwaf_ruleset_info_free(&info);
}

TEST(TestParserV2Interface, TestMultipleDiffInvalidRules)
{
    auto rule = readFile("invalid_multiple_diff.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    auto errors = static_cast<ddwaf::parameter::map>(parameter(info.errors));
    EXPECT_EQ(errors.size(), 2);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(rules.size(), 1);
        EXPECT_NE(rules.find("1"), rules.end());
    }

    {
        auto it = errors.find("unknown processor: squash");
        EXPECT_NE(it, errors.end());

        auto rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(rules.size(), 1);
        EXPECT_NE(rules.find("2"), rules.end());
    }

    EXPECT_EQ(info.failed, 2);
    EXPECT_EQ(info.loaded, 0);

    ddwaf_ruleset_info_free(&info);
}

TEST(TestParserV2Interface, TestMultipleMixInvalidRules)
{
    auto rule = readFile("invalid_multiple_mix.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    auto errors = static_cast<ddwaf::parameter::map>(parameter(info.errors));
    EXPECT_EQ(errors.size(), 3);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(rules.size(), 2);
        EXPECT_NE(rules.find("1"), rules.end());
        EXPECT_NE(rules.find("3"), rules.end());
    }

    {
        auto it = errors.find("unknown processor: squash");
        EXPECT_NE(it, errors.end());

        auto rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(rules.size(), 1);
        EXPECT_NE(rules.find("2"), rules.end());
    }

    {
        auto it = errors.find("missing key 'inputs'");
        EXPECT_NE(it, errors.end());

        auto rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(rules.size(), 1);
        EXPECT_NE(rules.find("4"), rules.end());
    }

    EXPECT_EQ(info.failed, 4);
    EXPECT_EQ(info.loaded, 1);

    ddwaf_ruleset_info_free(&info);

    ddwaf_destroy(handle);
}

TEST(TestParserV2Interface, TestInvalidDuplicate)
{
    auto rule = readFile("invalid_duplicate.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    auto errors = static_cast<ddwaf::parameter::map>(parameter(info.errors));
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("duplicate rule");
    EXPECT_NE(it, errors.end());

    auto rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(rules.size(), 1);
    EXPECT_NE(rules.find("1"), rules.end());

    EXPECT_EQ(info.failed, 1);
    EXPECT_EQ(info.loaded, 1);

    ddwaf_ruleset_info_free(&info);

    ddwaf_destroy(handle);
}

TEST(TestParserV2Interface, TestInvalidRuleset)
{
    auto rule = readFile("invalid_ruleset.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_ruleset_info info;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &info);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    auto errors = static_cast<ddwaf::parameter::map>(parameter(info.errors));
    EXPECT_EQ(errors.size(), 20);

    EXPECT_EQ(info.failed, 400);
    EXPECT_EQ(info.loaded, 0);

    for (auto &[key, value] : errors) {
        auto rules = static_cast<ddwaf::parameter::vector>(parameter(value));
        EXPECT_EQ(rules.size(), 20);
    }
    ddwaf_ruleset_info_free(&info);

    ddwaf_destroy(handle);
}
