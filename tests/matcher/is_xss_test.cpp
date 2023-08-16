// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test_utils.hpp"
#include "matcher/is_xss.hpp"

using namespace ddwaf::matcher;

namespace {
TEST(TestIsXSS, TestBasic)
{
    is_xss matcher;
    EXPECT_STREQ(matcher.to_string().data(), "");
    EXPECT_STREQ(matcher.name().data(), "is_xss");

    ddwaf_object param;
    ddwaf_object_string(&param, "<script>alert(1);</script>");

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STREQ(highlight.c_str(), "");

    ddwaf_object_free(&param);
}

TEST(TestIsXSS, TestNoMatch)
{
    is_xss matcher;

    ddwaf_object param;
    ddwaf_object_string(&param, "non-xss");

    EXPECT_FALSE(matcher.match(param).first);

    ddwaf_object_free(&param);
}

TEST(TestIsXSS, TestInvalidInput)
{
    is_xss matcher;

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"*", 0}).first);
}

TEST(TestIsXSS, TestRuleset)
{
    // Initialize a PowerWAF rule
    auto rule = yaml_to_object(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: is_xss, parameters: {inputs: [{address: arg1}]}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param;
    ddwaf_object tmp;
    ddwaf_object_map(&param);
    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "<script>alert(1);</script>"));

    ddwaf_result ret;

    auto code = ddwaf_run(context, &param, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MATCH);
    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{
                               .op = "is_xss",
                               .address = "arg1",
                               .value = "<script>alert(1);</script>",
                           }}});
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
