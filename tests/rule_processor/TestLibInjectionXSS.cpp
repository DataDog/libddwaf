// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"

TEST(TestLibInjectionXSS, TestBasic)
{
    LibInjectionXSS processor;
    EXPECT_STREQ(processor.getStringRepresentation().c_str(), "(null)");
    EXPECT_STREQ(processor.operatorName().data(), "is_xss");

    std::vector<uint8_t> matchestogather;
    MatchGatherer gatherer(matchestogather);
    ddwaf_object param;
    ddwaf_object_string(&param, "<script>alert(1);</script>");

    EXPECT_TRUE(processor.doesMatch(&param, gatherer));

    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "<script>alert(1);</script>");

    ddwaf_object_free(&param);
}

TEST(TestLibInjectionXSS, TestRuleset)
{
    //Initialize a PowerWAF rule
    auto rule = readRule(R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: is_xss, parameters: {inputs: [{address: arg1}]}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    ddwaf_object param, tmp;
    ddwaf_object_map(&param);
    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "<script>alert(1);</script>"));

    ddwaf_result ret;

    auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MONITOR);
    EXPECT_EQ(ret.action, DDWAF_MONITOR);
    EXPECT_STREQ(ret.data, R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"flow1","category":"category1"}},"rule_matches":[{"operator":"is_xss","operator_value":"","parameters":[{"address":"arg1","key_path":[],"value":"<script>alert(1);</script>","highlight":[]}]}]}])");
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
