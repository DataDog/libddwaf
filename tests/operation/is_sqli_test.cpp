// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"

using namespace ddwaf::operation;

TEST(TestIsSQLi, TestBasic)
{
    is_sqli processor;
    EXPECT_STREQ(processor.to_string().data(), "");
    EXPECT_STREQ(processor.name().data(), "is_sqli");

    ddwaf_object param;
    ddwaf_object_string(&param, "'OR 1=1/*");

    auto match = processor.match_object(param);
    EXPECT_TRUE(match);
    EXPECT_STREQ(match->resolved.c_str(), "'OR 1=1/*");

    ddwaf_object_free(&param);
}

TEST(TestIsSQLi, TestNoMatch)
{
    is_sqli processor;

    ddwaf_object param;
    ddwaf_object_string(&param, "*");

    EXPECT_FALSE(processor.match_object(param));

    ddwaf_object_free(&param);
}

TEST(TestIsSQLi, TestInvalidInput)
{
    is_sqli processor;

    EXPECT_FALSE(processor.match({nullptr, 0}));
    EXPECT_FALSE(processor.match({nullptr, 30}));
    EXPECT_FALSE(processor.match({"*", 0}));
}

TEST(TestIsSQLi, TestRuleset)
{
    // Initialize a PowerWAF rule
    auto rule = readRule(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: is_sqli, parameters: {inputs: [{address: arg1}]}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param, tmp;
    ddwaf_object_map(&param);
    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "'OR 1=1/*"));

    ddwaf_result ret;

    auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MATCH);
    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret,
        {.id = "1",
            .name = "rule1",
            .tags = {{"type", "flow1"}, {"category", "category1"}},
            .matches = {
                {.op = "is_sqli", .address = "arg1", .value = "'OR 1=1/*", .highlight = "s&1c"}}});
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
