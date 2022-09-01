// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestWaf, RootAddresses)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf::ruleset_info info;
    std::unique_ptr<ddwaf::waf> instance(waf::from_config(rule, nullptr, info));
    ddwaf_object_free(&rule);

    std::set<std::string_view> available_addresses{"value1", "value2"};
    for (auto address : instance->get_root_addresses()) {
        EXPECT_NE(available_addresses.find(address), available_addresses.end());
    }
}

TEST(TestWaf, BasicContextRun)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf::ruleset_info info;
    std::unique_ptr<ddwaf::waf> instance(waf::from_config(rule, nullptr, info));
    ddwaf_object_free(&rule);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));

    auto ctx = instance->create_context();
    EXPECT_EQ(ctx.run(root, std::nullopt, LONG_TIME), DDWAF_MATCH);
}

TEST(TestWaf, ToggleRule)
{
    auto rule = readFile("toggle_rules.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf::ruleset_info info;
    std::unique_ptr<ddwaf::waf> instance(waf::from_config(rule, nullptr, info));
    ddwaf_object_free(&rule);

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));

        auto ctx = instance->create_context();
        EXPECT_EQ(ctx.run(root, std::nullopt, LONG_TIME), DDWAF_MATCH);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "id-rule-1", ddwaf_object_bool(&tmp, false));

        EXPECT_NO_THROW(instance->toggle_rules(parameter(root)));

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));

        auto ctx = instance->create_context();
        EXPECT_EQ(ctx.run(root, std::nullopt, LONG_TIME), DDWAF_OK);
    }
}

TEST(TestWaf, ToggleNonExistentRules)
{
    auto rule = readFile("toggle_rules.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf::ruleset_info info;
    std::unique_ptr<ddwaf::waf> instance(waf::from_config(rule, nullptr, info));
    ddwaf_object_free(&rule);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "id-rule-4", ddwaf_object_bool(&tmp, false));

    EXPECT_NO_THROW(instance->toggle_rules(parameter(root)));

    ddwaf_object_free(&root);
}

TEST(TestWaf, ToggleWithInvalidObject)
{
    auto rule = readFile("toggle_rules.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf::ruleset_info info;
    std::unique_ptr<ddwaf::waf> instance(waf::from_config(rule, nullptr, info));
    ASSERT_NE(instance.get(), nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_object root, tmp;
        ddwaf_object_array(&root);
        ddwaf_object_array_add(&root, ddwaf_object_bool(&tmp, false));

        EXPECT_THROW(instance->toggle_rules(parameter(root)), ddwaf::bad_cast);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "id-rule-1", ddwaf_object_unsigned(&tmp, 5));

        EXPECT_THROW(instance->toggle_rules(parameter(root)), ddwaf::bad_cast);

        ddwaf_object_free(&root);
    }
}


