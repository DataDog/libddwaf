// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestParser, TestV1)
{
    auto rule = readRule(R"({version: '1.1', events: [{id: 1, tags: {type: flow1}, conditions: [{operation: match_regex, parameters: {inputs: [arg1], regex: .*}}, {operation: match_regex, parameters: {inputs: [arg2], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);

    ddwaf_object_free(&rule);
    ddwaf_destroy(handle);
}

TEST(TestParser, TestV2)
{
    auto rule = readRule(R"({version: '2.1', rules: [{id: 1, tags: {type: flow1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2}], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);

    ddwaf_object_free(&rule);
    ddwaf_destroy(handle);
}
