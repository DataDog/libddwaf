// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../test_utils.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/regressions/";

TEST(TestRegressionsIntegration, TruncatedUTF8)
{
    auto rule = read_file("regressions.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    char buffer[DDWAF_MAX_STRING_LENGTH + 4] = {0};
    const uint8_t emoji[] = {0xe2, 0x98, 0xa2};
    memset(buffer, 'A', sizeof(buffer));
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH - 2], emoji, sizeof(emoji));

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_stringl(&string, buffer, sizeof(buffer));
    ddwaf_object_map_add(&map, "value", &string);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    // The emoji should be trimmed out of the result
    std::string data = ddwaf::test::object_to_json(out.events);
    EXPECT_TRUE(memchr(data.c_str(), emoji[0], data.size()) == nullptr);

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRegressionsIntegration, DuplicateFlowMatches)
{
    auto rule = read_file("regressions2.yaml", base_dir);
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

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &ret, LONG_TIME), DDWAF_MATCH);

    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category2"}},
                           .matches = {{.op = "match_regex",
                                           .op_value = "Sqreen",
                                           .address = "param1",
                                           .value = "Sqreen",
                                           .highlight = "Sqreen"},
                               {.op = "match_regex",
                                   .op_value = "Duplicate",
                                   .address = "param2",
                                   .value = "Duplicate",
                                   .highlight = "Duplicate"}}});

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
