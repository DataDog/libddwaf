// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"

TEST(TestLibInjectionSQL, TestBasic)
{
    LibInjectionSQL processor;
    EXPECT_STREQ(processor.getStringRepresentation().c_str(), "(null)");
    EXPECT_STREQ(processor.operatorName().data(), "is_sqli");

    std::vector<uint8_t> matchestogather;
    MatchGatherer gatherer(matchestogather);
    ddwaf_object param;
    ddwaf_object_string(&param, "'OR 1=1/*");

    EXPECT_TRUE(processor.doesMatch(&param, gatherer));

    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "'OR 1=1/*");

    ddwaf_object_free(&param);
}

TEST(TestLibInjectionSQL, TestRuleset)
{
    //Initialize a PowerWAF rule
    auto rule = readRule(R"({version: '1.1', events: [{id: 1, tags: {type: flow1}, conditions: [{operation: is_sqli, parameters: {inputs: [arg1]}}], action: record}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    ddwaf_object param, tmp;
    ddwaf_object_map(&param);
    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "'OR 1=1/*"));

    ddwaf_result ret;

    auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MONITOR);
    EXPECT_EQ(ret.action, DDWAF_MONITOR);
    EXPECT_STREQ(ret.data, R"([{"ret_code":1,"flow":"flow1","rule":"1","filter":[{"operator":"is_sqli","binding_accessor":"arg1","manifest_key":"arg1","resolved_value":"'OR 1=1/*","match_status":"s&1c"}]}])");
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
