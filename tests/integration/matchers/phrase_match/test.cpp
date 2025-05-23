// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/matchers/phrase_match/";

TEST(TestPhraseMatchMatcherIntegration, Match)
{
    auto rule = read_file<ddwaf_object>("phrase_match.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_string(&value, "string00");
    ddwaf_object_map_add(&map, "input1", &value);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1-phrase-match",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "phrase_match",
                               .highlight = "string00"sv,
                               .args = {{
                                   .value = "string00"sv,
                                   .address = "input1",
                               }}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPhraseMatchMatcherIntegration, MatchWordBound)
{
    auto rule = read_file<ddwaf_object>("phrase_match.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object value;
        ddwaf_object_string(&value, "string01;");
        ddwaf_object_map_add(&map, "input2", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2-phrase-match-word-bound",
                               .tags = {{"type", "flow"}, {"category", "category"}},
                               .matches = {{.op = "phrase_match",
                                   .highlight = "string01"sv,
                                   .args = {{
                                       .value = "string01;"sv,
                                       .address = "input2",
                                   }}}}});

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object value;
        ddwaf_object_string(&value, "string010");
        ddwaf_object_map_add(&map, "input2", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

} // namespace
