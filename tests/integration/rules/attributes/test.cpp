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
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value1"), alloc), STRL("rule1"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context1, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule1"));
        EXPECT_NE(tag, nullptr);
        EXPECT_TRUE((ddwaf_object_get_type(tag) & DDWAF_OBJ_STRING) != 0);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "something"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, alloc);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, SingleValueOutputAndEvent)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value2"), alloc), STRL("rule2"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context1, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        EXPECT_EVENTS(result, {.id = "rule2",
                                  .name = "rule2",
                                  .tags = {{"type", "flow2"}, {"category", "category2"}},
                                  .matches = {{.op = "match_regex",
                                      .op_value = "^rule2$",
                                      .highlight = "rule2"sv,
                                      .args = {{.value = "rule2"sv, .address = "value2"}}}}});

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule2"));
        EXPECT_NE(tag, nullptr);
        EXPECT_TRUE((ddwaf_object_get_type(tag) & DDWAF_OBJ_STRING) != 0);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "something"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, alloc);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, SingleTargetOutputNoEvent)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value3"), alloc), STRL("rule3"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context1, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule3"));
        EXPECT_NE(tag, nullptr);
        EXPECT_TRUE((ddwaf_object_get_type(tag) & DDWAF_OBJ_STRING) != 0);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "rule3"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, alloc);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, MultipleValuesOutputNoEvent)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value4"), alloc), STRL("rule4"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context1, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 4);

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("rule4.int64"));
            EXPECT_NE(tag, nullptr);
            EXPECT_EQ(ddwaf_object_get_type(tag), DDWAF_OBJ_SIGNED);
            EXPECT_EQ(ddwaf_object_get_signed(tag), -200);
        }

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("rule4.uint64"));
            EXPECT_NE(tag, nullptr);
            EXPECT_EQ(ddwaf_object_get_type(tag), DDWAF_OBJ_UNSIGNED);
            EXPECT_EQ(ddwaf_object_get_unsigned(tag), 200);
        }

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("rule4.double"));
            EXPECT_NE(tag, nullptr);
            EXPECT_EQ(ddwaf_object_get_type(tag), DDWAF_OBJ_FLOAT);
            EXPECT_EQ(ddwaf_object_get_float(tag), 200.22);
        }

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("rule4.bool"));
            EXPECT_NE(tag, nullptr);
            EXPECT_EQ(ddwaf_object_get_type(tag), DDWAF_OBJ_BOOL);
            EXPECT_TRUE(ddwaf_object_get_bool(tag));
        }

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, alloc);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, AttributesWithActions)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value5"), alloc), STRL("rule5"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context1, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule5"));
        EXPECT_NE(tag, nullptr);
        EXPECT_TRUE((ddwaf_object_get_type(tag) & DDWAF_OBJ_STRING) != 0);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "rule5"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_TRUE(ddwaf_object_get_bool(keep));

        const auto *actions = ddwaf_object_find(&result, STRL("actions"));
        EXPECT_NE(actions, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(actions), 1);

        const auto *action = ddwaf_object_find(actions, STRL("block_request"));
        EXPECT_NE(action, nullptr);

        ddwaf_object_destroy(&result, alloc);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, MultipleAttributesAndActions)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 2, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value5"), alloc), STRL("rule5"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value6"), alloc), STRL("rule6"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context1, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 2);

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("result.rule5"));
            EXPECT_NE(tag, nullptr);
            EXPECT_TRUE((ddwaf_object_get_type(tag) & DDWAF_OBJ_STRING) != 0);

            std::size_t length;
            const auto *str = ddwaf_object_get_string(tag, &length);

            std::string_view value{str, length};
            EXPECT_EQ(value, "rule5"sv);
        }

        {
            const auto *tag = ddwaf_object_find(attributes, STRL("result.rule6"));
            EXPECT_NE(tag, nullptr);
            EXPECT_TRUE((ddwaf_object_get_type(tag) & DDWAF_OBJ_STRING) != 0);

            std::size_t length;
            const auto *str = ddwaf_object_get_string(tag, &length);

            std::string_view value{str, length};
            EXPECT_EQ(value, "rule6"sv);
        }

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_TRUE(ddwaf_object_get_bool(keep));

        const auto *actions = ddwaf_object_find(&result, STRL("actions"));
        EXPECT_NE(actions, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(actions), 2);

        const auto *block_action = ddwaf_object_find(actions, STRL("block_request"));
        EXPECT_NE(block_action, nullptr);

        const auto *stack_action = ddwaf_object_find(actions, STRL("generate_stack"));
        EXPECT_NE(stack_action, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(stack_action), DDWAF_OBJ_MAP);

        EXPECT_NE(ddwaf_object_find(stack_action, STRL("stack_id")), nullptr);

        ddwaf_object_destroy(&result, alloc);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, AttributesAndMonitorRuleFilter)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value7"), alloc), STRL("rule7"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context1, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule7"));
        EXPECT_NE(tag, nullptr);
        EXPECT_TRUE((ddwaf_object_get_type(tag) & DDWAF_OBJ_STRING) != 0);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "rule7"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_TRUE(ddwaf_object_get_bool(keep));

        const auto *actions = ddwaf_object_find(&result, STRL("actions"));
        EXPECT_NE(actions, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(actions), 0);

        ddwaf_object_destroy(&result, alloc);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, AttributesAndBlockingRuleFilter)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value8"), alloc), STRL("rule8"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context1, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule8"));
        EXPECT_NE(tag, nullptr);
        EXPECT_TRUE((ddwaf_object_get_type(tag) & DDWAF_OBJ_STRING) != 0);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "rule8"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        const auto *actions = ddwaf_object_find(&result, STRL("actions"));
        EXPECT_NE(actions, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(actions), 1);

        const auto *action = ddwaf_object_find(actions, STRL("block_request"));
        EXPECT_NE(action, nullptr);

        ddwaf_object_destroy(&result, alloc);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, AttributesAndSubcontextMatches)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        // No Match
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value1"), alloc), STRL("rule8"));

        auto *subctx = ddwaf_subcontext_init(context1);

        ddwaf_object result;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &parameter, alloc, &result, LONG_TIME), DDWAF_OK);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

        ddwaf_object_destroy(&result, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        // The first match should contain attributes
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value1"), alloc), STRL("rule1"));

        auto *subctx = ddwaf_subcontext_init(context1);

        ddwaf_object result;
        EXPECT_EQ(
            ddwaf_subcontext_eval(subctx, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        ddwaf_object_destroy(&result, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        // The second match should contain attributes
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value1"), alloc), STRL("rule1"));

        auto *subctx = ddwaf_subcontext_init(context1);

        ddwaf_object result;
        EXPECT_EQ(
            ddwaf_subcontext_eval(subctx, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        ddwaf_object_destroy(&result, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, AttributesEventsAndSubcontextMatches)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context1 = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        // No Match
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value2"), alloc), STRL("rule8"));

        auto *subctx = ddwaf_subcontext_init(context1);

        ddwaf_object result;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &parameter, alloc, &result, LONG_TIME), DDWAF_OK);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        EXPECT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

        ddwaf_object_destroy(&result, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        // The first match should contain attributes
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value2"), alloc), STRL("rule2"));

        auto *subctx = ddwaf_subcontext_init(context1);

        ddwaf_object result;
        EXPECT_EQ(
            ddwaf_subcontext_eval(subctx, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        EXPECT_EVENTS(result, {.id = "rule2",
                                  .name = "rule2",
                                  .tags = {{"type", "flow2"}, {"category", "category2"}},
                                  .matches = {{.op = "match_regex",
                                      .op_value = "^rule2$",
                                      .highlight = "rule2"sv,
                                      .args = {{
                                          .value = "rule2"sv,
                                          .address = "value2",
                                      }}}}});

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        ddwaf_object_destroy(&result, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        // The second match should contain an event and attributes as well
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value2"), alloc), STRL("rule2"));

        auto *subctx = ddwaf_subcontext_init(context1);

        ddwaf_object result;
        EXPECT_EQ(
            ddwaf_subcontext_eval(subctx, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        EXPECT_EVENTS(result, {.id = "rule2",
                                  .name = "rule2",
                                  .tags = {{"type", "flow2"}, {"category", "category2"}},
                                  .matches = {{.op = "match_regex",
                                      .op_value = "^rule2$",
                                      .highlight = "rule2"sv,
                                      .args = {{
                                          .value = "rule2"sv,
                                          .address = "value2",
                                      }}}}});

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        ddwaf_object_destroy(&result, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context1);
}

TEST(TestRuleAttributesIntegration, InputAttributesInKnownAddresses)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 12);

    std::set<std::string_view> available_addresses{"value1", "value2", "value3", "value4", "value5",
        "value6", "value7", "value8", "value9", "value10", "output_value9", "output_value10"};
    while ((size--) != 0U) {
        EXPECT_NE(available_addresses.find(addresses[size]), available_addresses.end());
    }

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);
}

} // namespace
