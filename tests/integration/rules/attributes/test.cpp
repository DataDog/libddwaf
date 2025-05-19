// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/rules/attributes/";

TEST(TestRuleAttributesIntegration, SingleValueOutputNoEvent)
{
    auto rule = read_file("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule1"));
        EXPECT_NE(tag, nullptr);
        EXPECT_EQ(ddwaf_object_type(tag), DDWAF_OBJ_STRING);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "something"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_free(&result);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, SingleValueOutputAndEvent)
{
    auto rule = read_file("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2", ddwaf_object_string(&tmp, "rule2"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_type(&result), DDWAF_OBJ_MAP);

        EXPECT_EVENTS(result, {.id = "rule2",
                                  .name = "rule2",
                                  .tags = {{"type", "flow2"}, {"category", "category2"}},
                                  .matches = {{.op = "match_regex",
                                      .op_value = "^rule2",
                                      .highlight = "rule2"sv,
                                      .args = {{.value = "rule2"sv, .address = "value2"}}}}});

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule2"));
        EXPECT_NE(tag, nullptr);
        EXPECT_EQ(ddwaf_object_type(tag), DDWAF_OBJ_STRING);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "something"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_free(&result);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, SingleTargetOutputNoEvent)
{
    auto rule = read_file("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value3", ddwaf_object_string(&tmp, "rule3"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule3"));
        EXPECT_NE(tag, nullptr);
        EXPECT_EQ(ddwaf_object_type(tag), DDWAF_OBJ_STRING);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "rule3"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_free(&result);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, MultipleValuesOutputNoEvent)
{
    auto rule = read_file("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value4", ddwaf_object_string(&tmp, "rule4"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_size(attributes), 4);

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("rule4.int64"));
            EXPECT_NE(tag, nullptr);
            EXPECT_EQ(ddwaf_object_type(tag), DDWAF_OBJ_SIGNED);
            EXPECT_EQ(ddwaf_object_get_signed(tag), -200);
        }

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("rule4.uint64"));
            EXPECT_NE(tag, nullptr);
            EXPECT_EQ(ddwaf_object_type(tag), DDWAF_OBJ_UNSIGNED);
            EXPECT_EQ(ddwaf_object_get_unsigned(tag), 200);
        }

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("rule4.double"));
            EXPECT_NE(tag, nullptr);
            EXPECT_EQ(ddwaf_object_type(tag), DDWAF_OBJ_FLOAT);
            EXPECT_EQ(ddwaf_object_get_float(tag), 200.22);
        }

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("rule4.bool"));
            EXPECT_NE(tag, nullptr);
            EXPECT_EQ(ddwaf_object_type(tag), DDWAF_OBJ_BOOL);
            EXPECT_TRUE(ddwaf_object_get_bool(tag));
        }

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_free(&result);
    }

    ddwaf_context_destroy(context1);
}

} // namespace
