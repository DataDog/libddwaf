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
    auto rule = read_file<ddwaf_object>("global_transformer.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_0", ddwaf_object_string(&tmp, "RULE1"));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_1", ddwaf_object_string(&tmp, "RULE1"));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2_0", ddwaf_object_string(&tmp, "  RULE2    "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2_1", ddwaf_object_string(&tmp, "      RULE2   "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, GlobalTransformerKeysOnly)
{
    auto rule = read_file<ddwaf_object>("global_transformer.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "RULE3", ddwaf_object_string(&tmp, "randomvalue"));
        ddwaf_object_map_add(&parameter, "value3_0", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "key", ddwaf_object_string(&tmp, "RULE3"));
        ddwaf_object_map_add(&parameter, "value3_0", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "key", ddwaf_object_string(&tmp, "RULE3"));
        ddwaf_object_map_add(&parameter, "value3_1", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "RULE3", ddwaf_object_string(&tmp, "randomvalue"));
        ddwaf_object_map_add(&parameter, "value3_1", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, InputTransformer)
{
    auto rule = read_file<ddwaf_object>("input_transformer.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_0", ddwaf_object_string(&tmp, "RULE1"));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_1", ddwaf_object_string(&tmp, "RULE1"));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2_0", ddwaf_object_string(&tmp, "  RULE2    "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2_1", ddwaf_object_string(&tmp, "      RULE2   "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, InputTransformerKeysOnly)
{
    auto rule = read_file<ddwaf_object>("input_transformer.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "RULE3", ddwaf_object_string(&tmp, "randomvalue"));
        ddwaf_object_map_add(&parameter, "value3_0", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "key", ddwaf_object_string(&tmp, "RULE3"));
        ddwaf_object_map_add(&parameter, "value3_0", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "key", ddwaf_object_string(&tmp, "RULE3"));
        ddwaf_object_map_add(&parameter, "value3_1", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "RULE3", ddwaf_object_string(&tmp, "randomvalue"));
        ddwaf_object_map_add(&parameter, "value3_1", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, OverlappingTransformer)
{
    auto rule = read_file<ddwaf_object>("overlapping_transformers.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_0", ddwaf_object_string(&tmp, " RULE1 "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_0", ddwaf_object_string(&tmp, "    rule1 "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_1", ddwaf_object_string(&tmp, " rule1 "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_1", ddwaf_object_string(&tmp, " RULE1 "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_2", ddwaf_object_string(&tmp, "   rule1   "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_2", ddwaf_object_string(&tmp, "  RULE1   "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1_3", ddwaf_object_string(&tmp, "    RULE1   "));

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestConditionTransformersIntegration, OverlappingTransformerKeysOnly)
{
    auto rule = read_file<ddwaf_object>("overlapping_transformers.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, ddwaf_object_free};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    /*    {*/
    /*ddwaf_context context = ddwaf_context_init(handle);*/
    /*ASSERT_NE(context, nullptr);*/

    /*ddwaf_object parameter = DDWAF_OBJECT_MAP;*/
    /*ddwaf_object map = DDWAF_OBJECT_MAP;*/
    /*ddwaf_object_map_add(&map, "rule2", ddwaf_object_string(&tmp, "value"));*/
    /*ddwaf_object_map_add(&parameter, "value2_0", &map);*/

    /*EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);*/

    /*ddwaf_context_destroy(context);*/
    /*}*/

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "rule2", ddwaf_object_string(&tmp, "value"));
        ddwaf_object_map_add(&parameter, "value2_1", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "value", ddwaf_object_string(&tmp, "rule2"));
        ddwaf_object_map_add(&parameter, "value2_1", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "value", ddwaf_object_string(&tmp, "RULE2"));
        ddwaf_object_map_add(&parameter, "value2_1", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "value", ddwaf_object_string(&tmp, "RULE2"));
        ddwaf_object_map_add(&parameter, "value2_2", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "rule2", ddwaf_object_string(&tmp, "value"));
        ddwaf_object_map_add(&parameter, "value2_2", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "rule2", ddwaf_object_string(&tmp, "value"));
        ddwaf_object_map_add(&parameter, "value2_3", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "value", ddwaf_object_string(&tmp, "rule2"));
        ddwaf_object_map_add(&parameter, "value2_3", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&map, "value", ddwaf_object_string(&tmp, "RULE2"));
        ddwaf_object_map_add(&parameter, "value2_3", &map);

        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

} // namespace
