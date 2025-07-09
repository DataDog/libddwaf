// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

using namespace ddwaf::matcher;
using namespace std::literals;

namespace {

TEST(TestIsXSSIntegration, Match)
{
    auto *alloc = ddwaf_get_default_allocator();
    // Initialize a WAF rule
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: is_xss, parameters: {inputs: [{address: arg1}]}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object param;
    ddwaf_object_set_map(&param, 1, alloc);

    auto *child = ddwaf_object_insert_key(&param, STRL("arg1"), alloc);
    ddwaf_object_set_string(child, STRL("<script>alert(1);</script>"), alloc);

    ddwaf_object ret;
    auto code = ddwaf_context_eval(context, &param, nullptr, true, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "is_xss",
                               .args = {{
                                   .value = "<script>alert(1);</script>"sv,
                                   .address = "arg1",
                               }}}}});
    ddwaf_object_destroy(&ret, alloc);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
