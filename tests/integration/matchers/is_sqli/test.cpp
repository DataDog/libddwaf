// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf::matcher;
using namespace std::literals;

namespace {

TEST(TestIsSQLiIntegration, Match)
{
    // Initialize a WAF rule
    auto rule = yaml_to_object<ddwaf_object>(
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

    ddwaf_object ret;

    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "is_sqli",
                               .highlight = "s&1c"sv,
                               .args = {{
                                   .value = "'OR 1=1/*"sv,
                                   .address = "arg1",
                               }}}}});
    ddwaf_object_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
