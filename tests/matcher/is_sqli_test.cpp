// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test_utils.hpp"
#include "matcher/is_sqli.hpp"

using namespace ddwaf::matcher;

namespace {

TEST(TestIsSQLi, TestBasic)
{
    is_sqli matcher;
    EXPECT_STREQ(matcher.to_string().data(), "");
    EXPECT_STREQ(matcher.name().data(), "is_sqli");

    ddwaf_object param;
    ddwaf_object_string(&param, "'OR 1=1/*");

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STREQ(highlight.c_str(), "s&1c");

    ddwaf_object_free(&param);
}

TEST(TestIsSQLi, TestMatch)
{
    is_sqli matcher;

    auto match = {"1, -sin(1)) UNION SELECT 1"};

    for (auto pattern : match) {
        ddwaf_object param;
        ddwaf_object_string(&param, pattern);
        EXPECT_TRUE(matcher.match(param).first);
        ddwaf_object_free(&param);
    }
}

TEST(TestIsSQLi, TestNoMatch)
{
    is_sqli matcher;

    auto no_match = {"*", "00119007249934829312950000808000953OR-240128165430155"};

    for (auto pattern : no_match) {
        ddwaf_object param;
        ddwaf_object_string(&param, pattern);
        EXPECT_FALSE(matcher.match(param).first);
        ddwaf_object_free(&param);
    }
}

TEST(TestIsSQLi, TestInvalidInput)
{
    is_sqli matcher;

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"*", 0}).first);
}

TEST(TestIsSQLi, TestRuleset)
{
    // Initialize a WAF rule
    auto rule = yaml_to_object(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: is_sqli, parameters: {inputs: [{address: arg1}]}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param;
    ddwaf_object tmp;
    ddwaf_object_map(&param);
    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "'OR 1=1/*"));

    ddwaf_result ret;

    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MATCH);
    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "is_sqli",
                               .highlight = "s&1c",
                               .args = {{
                                   .value = "'OR 1=1/*",
                                   .address = "arg1",
                               }}}}});
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
