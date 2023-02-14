// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
#include "test.h"

using namespace ddwaf;

TEST(TestInterface, RootAddresses)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_required_addresses(handle, &size);
    EXPECT_EQ(size, 2);

    std::set<std::string_view> available_addresses{"value1", "value2"};
    while ((size--) != 0U) {
        EXPECT_NE(available_addresses.find(addresses[size]), available_addresses.end());
    }

    ddwaf_destroy(handle);
}

TEST(TestInterface, HandleLifetime)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;
    ddwaf_object param_key = DDWAF_OBJECT_ARRAY, param_val = DDWAF_OBJECT_ARRAY;

    ddwaf_object_array_add(&param_key, ddwaf_object_unsigned(&tmp, 4242));
    ddwaf_object_array_add(&param_key, ddwaf_object_string(&tmp, "randomString"));

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object_map_add(&parameter, "value1", &param_key);
    ddwaf_object_map_add(&parameter, "value2", &param_val);

    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

    ddwaf_object_free(&parameter);
    ddwaf_context_destroy(context);
}

TEST(TestInterface, HandleLifetimeMultipleContexts)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle);
    ASSERT_NE(context2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;
    ddwaf_object param_key = DDWAF_OBJECT_ARRAY;
    ddwaf_object param_val = DDWAF_OBJECT_ARRAY;

    ddwaf_object_array_add(&param_key, ddwaf_object_unsigned(&tmp, 4242));
    ddwaf_object_array_add(&param_key, ddwaf_object_string(&tmp, "randomString"));

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object_map_add(&parameter, "value1", &param_key);
    ddwaf_object_map_add(&parameter, "value2", &param_val);

    EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
    ddwaf_context_destroy(context1);

    EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
    ddwaf_context_destroy(context2);

    ddwaf_object_free(&parameter);
}

TEST(TestInterface, UpdateEmpty)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    rule = readRule("{}");
    ddwaf_handle new_handle = ddwaf_update(handle, &rule, nullptr);
    ASSERT_EQ(new_handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_destroy(handle);
}

TEST(TestInterface, UpdateRules)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    rule = readFile("interface3.yaml");
    ddwaf_handle new_handle = ddwaf_update(handle, &rule, nullptr);
    ASSERT_NE(new_handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context2 = ddwaf_context_init(new_handle);
    ASSERT_NE(context2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);
    ddwaf_destroy(new_handle);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context1);
}

TEST(TestInterface, UpdateInvalidRules)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    rule = readRule("{rules: []}");
    ddwaf_handle new_handle = ddwaf_update(handle, &rule, nullptr);
    ASSERT_EQ(new_handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_destroy(handle);
}

TEST(TestInterface, UpdateDisableEnableRuleByID)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_handle handle2;
    {
        auto overrides =
            readRule(R"({rules_override: [{rules_target: [{rule_id: 1}], enabled: false}]})");
        handle2 = ddwaf_update(handle1, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto overrides = readRule(R"({rules_override: []})");
        handle3 = ddwaf_update(handle2, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    ddwaf_context context3 = ddwaf_context_init(handle3);
    ASSERT_NE(context3, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateDisableEnableRuleByTags)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_handle handle2;
    {
        auto overrides = readRule(
            R"({rules_override: [{rules_target: [{tags: {type: flow2}}], enabled: false}]})");
        handle2 = ddwaf_update(handle1, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto overrides = readRule(R"({rules_override: []})");
        handle3 = ddwaf_update(handle2, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    ddwaf_context context3 = ddwaf_context_init(handle3);
    ASSERT_NE(context3, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule2"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateActionsByID)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto overrides =
            readRule(R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [block]}]})");
        handle2 = ddwaf_update(handle1, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_result result1;
        ddwaf_result result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(result1.actions.size, 0);
        EXPECT_EQ(result2.actions.size, 1);
        EXPECT_STREQ(result2.actions.array[0], "block");

        ddwaf_result_free(&result1);
        ddwaf_result_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule2"));

        ddwaf_result result1;
        ddwaf_result result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(result1.actions.size, 0);
        EXPECT_EQ(result2.actions.size, 0);

        ddwaf_result_free(&result1);
        ddwaf_result_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto overrides =
            readRule(R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [redirect]}]})");
        handle3 = ddwaf_update(handle2, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    {
        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_result result2;
        ddwaf_result result3;

        EXPECT_EQ(ddwaf_run(context2, &parameter, &result2, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, &result3, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(result2.actions.size, 1);
        EXPECT_EQ(result3.actions.size, 1);
        EXPECT_STREQ(result2.actions.array[0], "block");
        EXPECT_STREQ(result3.actions.array[0], "redirect");

        ddwaf_result_free(&result2);
        ddwaf_result_free(&result3);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context3);
    }

    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateActionsByTags)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto overrides = readRule(
            R"({rules_override: [{rules_target: [{tags: {confidence: 1}}], on_match: [block]}]})");
        handle2 = ddwaf_update(handle1, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_result result1;
        ddwaf_result result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(result1.actions.size, 0);
        EXPECT_EQ(result2.actions.size, 1);
        EXPECT_STREQ(result2.actions.array[0], "block");

        ddwaf_result_free(&result1);
        ddwaf_result_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule2"));

        ddwaf_result result1;
        ddwaf_result result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(result1.actions.size, 0);
        EXPECT_EQ(result2.actions.size, 0);

        ddwaf_result_free(&result1);
        ddwaf_result_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
}

TEST(TestInterface, UpdateInvalidOverrides)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto overrides = readRule(R"({rules_override: [{enabled: false}]})");
    ddwaf_handle handle2 = ddwaf_update(handle1, &overrides, nullptr);
    ASSERT_EQ(handle2, nullptr);
    ddwaf_object_free(&overrides);

    ddwaf_destroy(handle1);
}

TEST(TestInterface, UpdateRuleData)
{
    auto rule = readFile("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto data = readRule(
            R"({rules_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 0}]}]})");
        handle2 = ddwaf_update(handle1, &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_handle handle3;
    {
        auto data = readRule(
            R"({rules_data: [{id: usr_data, type: data_with_expiration, data: [{value: paco, expiration: 0}]}]})");
        handle3 = ddwaf_update(handle2, &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    ddwaf_context context3 = ddwaf_context_init(handle3);
    ASSERT_NE(context3, nullptr);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateInvalidRuleData)
{
    auto rule = readFile("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    // A rules_data with unrelated keys is considered an empty rules_data
    auto data = readRule(
        R"({rules_data: [{id: ipo_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 0}]}]})");
    ddwaf_handle handle2 = ddwaf_update(handle1, &data, nullptr);
    EXPECT_NE(handle2, nullptr);
    ddwaf_object_free(&data);

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
}

TEST(TestInterface, UpdateRuleExclusions)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto exclusions = readRule(R"({exclusions: [{id: 1, rules_target: [{rule_id: 1}]}]})");
        handle2 = ddwaf_update(handle1, &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto exclusions = readRule(R"({exclusions: []})");
        handle3 = ddwaf_update(handle2, &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    {
        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context3);
        ddwaf_context_destroy(context2);
    }

    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateInputExclusions)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto exclusions = readRule(R"({exclusions: [{id: 1, inputs: [{address: value1}]}]})");
        handle2 = ddwaf_update(handle1, &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2", ddwaf_object_string(&tmp, "rule3"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto exclusions = readRule(R"({exclusions: []})");
        handle3 = ddwaf_update(handle2, &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    {
        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context3);
        ddwaf_context_destroy(context2);
    }

    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}
