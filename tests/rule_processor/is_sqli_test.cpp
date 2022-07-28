// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"

using namespace ddwaf::rule_processor;

TEST(TestIsSQLi, TestBasic)
{
    is_sqli processor;
    EXPECT_STREQ(processor.to_string().c_str(), "");
    EXPECT_STREQ(processor.name().data(), "is_sqli");

    MatchGatherer gatherer;
    ddwaf_object param;
    ddwaf_object_string(&param, "'OR 1=1/*");

    EXPECT_TRUE(processor.match_object(&param, gatherer));

    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "'OR 1=1/*");

    ddwaf_object_free(&param);
}

TEST(TestIsSQLi, TestNoMatch)
{
    is_sqli processor;
    EXPECT_STREQ(processor.to_string().c_str(), "");
    EXPECT_STREQ(processor.name().data(), "is_sqli");

    MatchGatherer gatherer;
    ddwaf_object param;
    ddwaf_object_string(&param, "*");

    EXPECT_FALSE(processor.match_object(&param, gatherer));

    ddwaf_object_free(&param);
}

TEST(TestIsSQLi, TestInvalidInput)
{
    is_sqli processor;
    EXPECT_STREQ(processor.to_string().c_str(), "");
    EXPECT_STREQ(processor.name().data(), "is_sqli");

    MatchGatherer gatherer;
    EXPECT_FALSE(processor.match(nullptr, 0,  gatherer));
    EXPECT_FALSE(processor.match(nullptr, 30,  gatherer));
    EXPECT_FALSE(processor.match("*", 0,  gatherer));
}

TEST(TestIsSQLi, TestRuleset)
{
    //Initialize a PowerWAF rule
    auto rule = readRule(R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: is_sqli, parameters: {inputs: [{address: arg1}]}}]}]})");
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
    EXPECT_EQ(code, DDWAF_MONITOR);
    EXPECT_FALSE(ret.timeout);
    EXPECT_STREQ(ret.data, R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"flow1","category":"category1"}},"rule_matches":[{"operator":"is_sqli","operator_value":"","parameters":[{"address":"arg1","key_path":[],"value":"'OR 1=1/*","highlight":["s&1c"]}]}]}])");
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
