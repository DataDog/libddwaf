// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"

using namespace ddwaf::operation;

TEST(TestRegexMatch, TestBasicCaseInsensitive)
{
    regex_match processor("^rEgEx$", 0, false);
    EXPECT_STREQ(processor.to_string().data(), "^rEgEx$");
    EXPECT_STREQ(processor.name().data(), "match_regex");

    ddwaf_object param;
    ddwaf_object_string(&param, "regex");

    auto match = processor.match_object(&param);
    EXPECT_TRUE(match);

    EXPECT_STREQ(match->resolved.c_str(), "regex");
    EXPECT_STREQ(match->matched.c_str(), "regex");

    ddwaf_object_free(&param);
}

TEST(TestRegexMatch, TestBasicCaseSensitive)
{
    regex_match processor("^rEgEx$", 0, true);

    ddwaf_object param;
    ddwaf_object_string(&param, "regex");

    EXPECT_FALSE(processor.match_object(&param));

    ddwaf_object param2;
    ddwaf_object_string(&param2, "rEgEx");

    auto match = processor.match_object(&param2);
    EXPECT_TRUE(match);

    EXPECT_STREQ(match->resolved.c_str(), "rEgEx");
    EXPECT_STREQ(match->matched.c_str(), "rEgEx");

    ddwaf_object_free(&param);
    ddwaf_object_free(&param2);
}

TEST(TestRegexMatch, TestMinLength)
{
    regex_match processor("^rEgEx.*$", 6, true);

    ddwaf_object param, param2;
    ddwaf_object_string(&param, "rEgEx");
    ddwaf_object_string(&param2, "rEgExe");

    EXPECT_FALSE(processor.match_object(&param));

    auto match = processor.match_object(&param2);
    EXPECT_TRUE(match);
    EXPECT_STREQ(match->resolved.c_str(), "rEgExe");
    EXPECT_STREQ(match->matched.c_str(), "rEgExe");

    ddwaf_object_free(&param);
    ddwaf_object_free(&param2);
}

TEST(TestRegexMatch, TestInvalidInput)
{
    regex_match processor("^rEgEx.*$", 6, true);

    EXPECT_FALSE(processor.match({nullptr, 0}));
    EXPECT_FALSE(processor.match({nullptr, 30}));
    EXPECT_FALSE(processor.match({"*", 0}));
}

TEST(TestRegexMatch, TestRulesetCaseSensitive)
{
    // Initialize a PowerWAF rule
    auto rule = readRule(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: alert, options: {case_sensitive: true}}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object param, tmp;
        ddwaf_object_map(&param);
        ddwaf_object_map_add(
            &param, "arg1", ddwaf_object_string(&tmp, "<script>alert(1);</script>"));

        ddwaf_result ret;

        auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_MATCH);
        EXPECT_FALSE(ret.timeout);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{
                                   .op = "match_regex",
                                   .op_value = "alert",
                                   .address = "arg1",
                                   .value = "<script>alert(1);</script>",
                                   .highlight = "alert",
                               }}});
        ddwaf_result_free(&ret);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object param, tmp;
        ddwaf_object_map(&param);
        ddwaf_object_map_add(
            &param, "arg1", ddwaf_object_string(&tmp, "<script>AlErT(1);</script>"));

        ddwaf_result ret;

        auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_OK);
        EXPECT_FALSE(ret.timeout);
        ddwaf_result_free(&ret);

        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRegexMatch, TestRulesetCaseInsensitive)
{
    // Initialize a PowerWAF rule
    auto rule = readRule(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: alert, options: {case_sensitive: false}}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object param, tmp;
        ddwaf_object_map(&param);
        ddwaf_object_map_add(
            &param, "arg1", ddwaf_object_string(&tmp, "<script>alert(1);</script>"));

        ddwaf_result ret;

        auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_MATCH);
        EXPECT_FALSE(ret.timeout);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{
                                   .op = "match_regex",
                                   .op_value = "alert",
                                   .address = "arg1",
                                   .value = "<script>alert(1);</script>",
                                   .highlight = "alert",
                               }}});
        ddwaf_result_free(&ret);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object param, tmp;
        ddwaf_object_map(&param);
        ddwaf_object_map_add(
            &param, "arg1", ddwaf_object_string(&tmp, "<script>AlErT(1);</script>"));

        ddwaf_result ret;

        auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{
                                   .op = "match_regex",
                                   .op_value = "alert",
                                   .address = "arg1",
                                   .value = "<script>AlErT(1);</script>",
                                   .highlight = "AlErT",
                               }}});

        EXPECT_FALSE(ret.timeout);
        ddwaf_result_free(&ret);

        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRegexMatch, TestRulesetMinLength)
{
    // Initialize a PowerWAF rule
    auto rule = readRule(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: alert, options: {min_length: 10}}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object param, tmp;
        ddwaf_object_map(&param);
        ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "alert("));

        ddwaf_result ret;

        auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_OK);
        ddwaf_result_free(&ret);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object param, tmp;
        ddwaf_object_map(&param);
        ddwaf_object_map_add(
            &param, "arg1", ddwaf_object_string(&tmp, "<script>AlErT(1);</script>"));

        ddwaf_result ret;

        auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{
                                   .op = "match_regex",
                                   .op_value = "alert",
                                   .address = "arg1",
                                   .value = "<script>AlErT(1);</script>",
                                   .highlight = "AlErT",
                               }}});

        EXPECT_FALSE(ret.timeout);
        ddwaf_result_free(&ret);

        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}
