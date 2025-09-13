// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/regressions/";

TEST(TestRegressionsIntegration, DuplicateFlowMatches)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("regressions2.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&parameter, STRL("param1"), alloc), STRL("Sqreen"), alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&parameter, STRL("param2"), alloc), STRL("Duplicate"), alloc);

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &ret, LONG_TIME), DDWAF_MATCH);

    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(ret, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category2"}},
                           .matches = {{.op = "match_regex",
                                           .op_value = "Sqreen",
                                           .highlight = "Sqreen"sv,
                                           .args = {{
                                               .value = "Sqreen"sv,
                                               .address = "param1",
                                           }}},
                               {.op = "match_regex",
                                   .op_value = "Duplicate",
                                   .highlight = "Duplicate"sv,
                                   .args = {{
                                       .value = "Duplicate"sv,
                                       .address = "param2",
                                   }}}}});

    ddwaf_object_destroy(&ret, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
