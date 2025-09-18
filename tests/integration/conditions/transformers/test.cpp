// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/conditions/transformers/";

TEST(TestConditionTransformersIntegration, GlobalTransformer)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("global_transformer.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value1_0"), alloc), STRL("RULE1"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value1_1"), alloc), STRL("RULE1"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value2_0"), alloc),
            STRL("  RULE2    "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value2_1"), alloc),
            STRL("      RULE2   "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, GlobalTransformerKeysOnly)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("global_transformer.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);

        auto *map = ddwaf_object_insert_key(&parameter, STRL("value3_0"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("RULE3"), alloc), STRL("randomvalue"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value3_0"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("key"), alloc), STRL("RULE3"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value3_1"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("key"), alloc), STRL("RULE3"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value3_1"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("RULE3"), alloc), STRL("randomvalue"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, InputTransformer)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("input_transformer.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value1_0"), alloc), STRL("RULE1"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value1_1"), alloc), STRL("RULE1"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value2_0"), alloc),
            STRL("  RULE2    "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value2_1"), alloc),
            STRL("      RULE2   "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, InputTransformerKeysOnly)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("input_transformer.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value3_0"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("RULE3"), alloc), STRL("randomvalue"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value3_0"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("key"), alloc), STRL("RULE3"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value3_1"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("key"), alloc), STRL("RULE3"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value3_1"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("RULE3"), alloc), STRL("randomvalue"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, OverlappingTransformer)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("overlapping_transformers.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value1_0"), alloc), STRL(" RULE1 "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value1_0"), alloc),
            STRL("    rule1 "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value1_1"), alloc), STRL(" rule1 "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value1_1"), alloc), STRL(" RULE1 "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value1_2"), alloc),
            STRL("   rule1   "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value1_2"), alloc),
            STRL("  RULE1   "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value1_3"), alloc),
            STRL("    RULE1   "), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, OverlappingTransformerKeysOnly)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("overlapping_transformers.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    /*    {*/
    /*ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());*/
    /*ASSERT_NE(context, nullptr);*/

    /*ddwaf_object parameter;
ddwaf_object_set_map(&parameter, 1, alloc);*/
    /*ddwaf_object map;
ddwaf_object_set_map(&map, 1, alloc);*/
    /*ddwaf_object_set_string(ddwaf_object_insert_key(&map, STRL("rule2"), alloc), STRL("value"),
     * alloc);*/
    /*ddwaf_object_map_add(&parameter, "value2_0", &map);*/

    /*EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME),
     * DDWAF_OK);*/

    /*ddwaf_context_destroy(context);*/
    /*}*/

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value2_1"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("rule2"), alloc), STRL("value"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value2_1"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("value"), alloc), STRL("rule2"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value2_1"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("value"), alloc), STRL("RULE2"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value2_2"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("value"), alloc), STRL("RULE2"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value2_2"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("rule2"), alloc), STRL("value"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value2_3"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("rule2"), alloc), STRL("value"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value2_3"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("value"), alloc), STRL("rule2"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        auto *map = ddwaf_object_insert_key(&parameter, STRL("value2_3"), alloc);
        ddwaf_object_set_map(map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(map, STRL("value"), alloc), STRL("RULE2"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

} // namespace
