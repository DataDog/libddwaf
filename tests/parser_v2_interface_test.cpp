// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
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

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::parser::at<std::string>(root_map, "ruleset_version");
    EXPECT_STREQ(version.c_str(), "1.2.7");

    auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::parser::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);

    auto failed = ddwaf::parser::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 0);

    auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 0);

    ddwaf_object_free(&diagnostics);

    run_test(handle);

    ddwaf_destroy(handle);
}

TEST(TestParserV2Interface, BasicWithUpdate)
{
    auto rule = readRule(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);

    {

        ddwaf::parameter root(diagnostics);
        auto root_map = static_cast<ddwaf::parameter::map>(root);

        auto version = ddwaf::parser::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");

        auto loaded = ddwaf::parser::at<parameter::vector>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);

        auto failed = ddwaf::parser::at<parameter::vector>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_handle new_handle = ddwaf_update(handle, &rule, &diagnostics);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf::parameter root(diagnostics);
        auto root_map = static_cast<ddwaf::parameter::map>(root);

        auto version = ddwaf::parser::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");

        auto loaded = ddwaf::parser::at<parameter::vector>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);

        auto failed = ddwaf::parser::at<parameter::vector>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_object_free(&rule);
    run_test(new_handle);

    ddwaf_destroy(handle);
    ddwaf_destroy(new_handle);
}

TEST(TestParserV2Interface, NullRuleset)
{
    ddwaf_object diagnostics;
    ddwaf_object_invalid(&diagnostics);
    ddwaf_handle handle = ddwaf_init(nullptr, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);

    EXPECT_EQ(diagnostics.type, DDWAF_OBJ_INVALID);
}

TEST(TestParserV2Interface, TestInvalidRule)
{
    auto rule = readFile("invalid_single.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::parser::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::parser::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);

    auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_free(&diagnostics);
}

TEST(TestParserV2Interface, TestMultipleSameInvalidRules)
{
    auto rule = readFile("invalid_multiple_same.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::parser::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::parser::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 2);

    auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 2);
    EXPECT_NE(error_rules.find("1"), error_rules.end());
    EXPECT_NE(error_rules.find("2"), error_rules.end());

    ddwaf_object_free(&diagnostics);
}

TEST(TestParserV2Interface, TestMultipleDiffInvalidRules)
{
    auto rule = readFile("invalid_multiple_diff.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::parser::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::parser::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 2);

    auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 2);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());
    }

    {
        auto it = errors.find("unknown processor: squash");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("2"), error_rules.end());
    }

    ddwaf_object_free(&diagnostics);
}

TEST(TestParserV2Interface, TestMultipleMixInvalidRules)
{
    auto rule = readFile("invalid_multiple_mix.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::parser::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);

    auto failed = ddwaf::parser::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 4);

    auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 3);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 2);
        EXPECT_NE(error_rules.find("1"), error_rules.end());
        EXPECT_NE(error_rules.find("3"), error_rules.end());
    }

    {
        auto it = errors.find("unknown processor: squash");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("2"), error_rules.end());
    }

    {
        auto it = errors.find("missing key 'inputs'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("4"), error_rules.end());
    }

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestParserV2Interface, TestInvalidDuplicate)
{
    auto rule = readFile("invalid_duplicate.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::parser::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);

    auto failed = ddwaf::parser::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);

    auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("duplicate rule");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestParserV2Interface, TestInvalidRuleset)
{
    auto rule = readFile("invalid_ruleset.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::parser::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::parser::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 400);

    auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 20);

    for (auto &[key, value] : errors) {
        auto rules = static_cast<ddwaf::parameter::vector>(parameter(value));
        EXPECT_EQ(rules.size(), 20);
    }

    ddwaf_object_free(&diagnostics);
}
