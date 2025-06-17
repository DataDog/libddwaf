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
    auto rule = read_file<ddwaf_object>("regressions2.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;
    ddwaf_object_map_add(&parameter, "param1", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&parameter, "param2", ddwaf_object_string(&tmp, "Duplicate"));

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);

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

    ddwaf_object_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
