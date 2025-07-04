// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf::matcher;
using namespace std::literals;

namespace {

TEST(TestHiddenAsciiMatchMatchIntegration, Match)
{
    // Initialize a WAF rule
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: hidden_ascii_match, parameters: {inputs: [{address: arg1}]}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        std::string input =
            "\xF3\xA0\x81\xB4\xF3\xA0\x81\xA8\xF3\xA0\x81\xA9\xF3\xA0\x81\xB3 "
            "\xF3\xA0\x81\xA9\xF3\xA0\x81\xB3 "
            "\xF3\xA0\x81\xA8\xF3\xA0\x81\xA9\xF3\xA0\x81\xA4\xF3\xA0\x81\xA4\xF3\xA0\x81\xA5\xF3"
            "\xA0\x81\xAE "
            "\xF3\xA0\x81\xA1\xF3\xA0\x81\xB3\xF3\xA0\x81\xA3\xF3\xA0\x81\xA9\xF3\xA0\x81\xA9";

        ddwaf_object param;
        ddwaf_object tmp;
        ddwaf_object_map(&param);
        ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, input.c_str()));
        ddwaf_object ret;

        auto code = ddwaf_context_eval(context, &param, nullptr, true, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "hidden_ascii_match",
                                   .highlight = "this is hidden ascii"sv,
                                   .args = {{
                                       .value = input,
                                       .address = "arg1",
                                   }}}}});
        ddwaf_object_free(&ret);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object param;
        ddwaf_object tmp;
        ddwaf_object_map(&param);
        ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "normal text"));

        ddwaf_object ret;

        auto code = ddwaf_context_eval(context, &param, nullptr, true, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        ddwaf_object_free(&ret);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

} // namespace
