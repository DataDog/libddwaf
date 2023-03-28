// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
#include "test.h"

using namespace ddwaf;

// Custom rules can be used instead of base rules
TEST(TestCustomRules, Init)
{
    auto rule = readFile("custom_rules.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "custom_rule1"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2", ddwaf_object_string(&tmp, "custom_rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
}

// Custom rules can work alongside base rules
TEST(TestCustomRules, InitWithBaseRules)
{
    auto rule = readFile("custom_rules_and_rules.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2", ddwaf_object_string(&tmp, "custom_rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
}

/*TEST(TestCustomRules, UpdateCustomRules)*/
/*{*/
/*auto rule = readFile("interface.yaml");*/
/*ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);*/

/*ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};*/

/*ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);*/
/*ASSERT_NE(handle, nullptr);*/
/*ddwaf_object_free(&rule);*/

/*ddwaf_context context1 = ddwaf_context_init(handle);*/
/*ASSERT_NE(context1, nullptr);*/

/*// Destroying the handle should not invalidate it*/
/*ddwaf_destroy(handle);*/

/*ddwaf_object tmp;*/
/*{*/
/*ddwaf_object parameter = DDWAF_OBJECT_MAP;*/
/*ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));*/

/*EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);*/

/*ddwaf_object_free(&parameter);*/
/*}*/

/*{*/
/*ddwaf_object parameter = DDWAF_OBJECT_MAP;*/
/*ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule2"));*/

/*EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);*/

/*ddwaf_object_free(&parameter);*/
/*}*/

/*ddwaf_context_destroy(context1);*/
/*}*/
