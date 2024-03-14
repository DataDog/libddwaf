// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test_utils.hpp"
#include "version.hpp"

using namespace ddwaf;

namespace {

TEST(TestInterface, Empty)
{
    auto rule = yaml_to_object("{}");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);
}

TEST(TestInterface, ddwaf_get_version) { EXPECT_STREQ(ddwaf_get_version(), LIBDDWAF_VERSION); }

TEST(TestInterface, HandleBad)
{
    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, ddwaf_object_free};

    ddwaf_object tmp;
    ddwaf_object object = DDWAF_OBJECT_INVALID;
    EXPECT_EQ(ddwaf_init(&object, &config, nullptr), nullptr);

    EXPECT_NO_FATAL_FAILURE(ddwaf_destroy(nullptr));

    ddwaf_object_string(&object, "value");
    EXPECT_EQ(ddwaf_run(nullptr, &object, nullptr, nullptr, 1), DDWAF_ERR_INVALID_ARGUMENT);
    ddwaf_object_free(&object);

    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object_string(&object, "value");
    EXPECT_EQ(ddwaf_run(context, &object, nullptr, nullptr, 1), DDWAF_ERR_INVALID_OBJECT);

    ddwaf_object_string(&object, "value");
    EXPECT_EQ(ddwaf_run(context, nullptr, &object, nullptr, 1), DDWAF_ERR_INVALID_OBJECT);

    object = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&object, "value1", ddwaf_object_string(&tmp, "value"));
    ddwaf_result res;
    EXPECT_EQ(ddwaf_run(context, &object, nullptr, &res, 0), DDWAF_OK);
    EXPECT_TRUE(res.timeout);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestInterface, RootAddresses)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 2);

    std::set<std::string_view> available_addresses{"value1", "value2"};
    while ((size--) != 0U) {
        EXPECT_NE(available_addresses.find(addresses[size]), available_addresses.end());
    }

    ddwaf_destroy(handle);
}

TEST(TestInterface, HandleLifetime)
{
    auto rule = read_file("interface.yaml");
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

    ddwaf_object_array_add(&param_key, ddwaf_object_string_from_unsigned(&tmp, 4242));
    ddwaf_object_array_add(&param_key, ddwaf_object_string(&tmp, "randomString"));

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object_map_add(&parameter, "value1", &param_key);
    ddwaf_object_map_add(&parameter, "value2", &param_val);

    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

    ddwaf_object_free(&parameter);
    ddwaf_context_destroy(context);
}

TEST(TestInterface, HandleLifetimeMultipleContexts)
{
    auto rule = read_file("interface.yaml");
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

    ddwaf_object_array_add(&param_key, ddwaf_object_string_from_unsigned(&tmp, 4242));
    ddwaf_object_array_add(&param_key, ddwaf_object_string(&tmp, "randomString"));

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object_map_add(&parameter, "value1", &param_key);
    ddwaf_object_map_add(&parameter, "value2", &param_val);

    EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    ddwaf_context_destroy(context1);

    EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    ddwaf_context_destroy(context2);

    ddwaf_object_free(&parameter);
}

TEST(TestInterface, InvalidVersion)
{
    auto rule = yaml_to_object("{version: 3.0, rules: []}");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_EQ(handle1, nullptr);
    ddwaf_object_free(&rule);
}

TEST(TestInterface, InvalidVersionNoRules)
{
    auto rule = yaml_to_object("{version: 3.0}");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_EQ(handle1, nullptr);
    ddwaf_object_free(&rule);
}

TEST(TestInterface, UpdateWithNullObject)
{
    EXPECT_EQ(ddwaf_update(nullptr, nullptr, nullptr), nullptr);
}

TEST(TestInterface, UpdateWithNullHandle)
{
    auto rule = read_file("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    EXPECT_EQ(ddwaf_update(handle, nullptr, nullptr), nullptr);
    ddwaf_destroy(handle);
}

TEST(TestInterface, UpdateEmpty)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    rule = yaml_to_object("{}");
    ddwaf_handle new_handle = ddwaf_update(handle, &rule, nullptr);
    ASSERT_EQ(new_handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_destroy(handle);
}

TEST(TestInterface, PreloadRuleData)
{
    auto rule = read_file("rule_data_with_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        auto root = yaml_to_object(
            R"({rules_data: [{id: usr_data, type: data_with_expiration, data: [{value: pepe, expiration: 0}]}, {id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.2, expiration: 0}]}]})");

        ddwaf_handle new_handle = ddwaf_update(handle, &root, nullptr);
        ASSERT_NE(new_handle, nullptr);
        ddwaf_object_free(&root);
        ddwaf_destroy(handle);

        handle = new_handle;
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestInterface, UpdateRules)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    rule = read_file("interface3.yaml");
    ddwaf_handle new_handle = ddwaf_update(handle, &rule, nullptr);
    ASSERT_NE(new_handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context2 = ddwaf_context_init(new_handle);
    ASSERT_NE(context2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);
    ddwaf_destroy(new_handle);

    ddwaf_object tmp;
    ddwaf_object parameter1 = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter1, "value1", ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object parameter2 = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter2, "value1", ddwaf_object_string(&tmp, "rule2"));

    EXPECT_EQ(ddwaf_run(context1, &parameter1, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    EXPECT_EQ(ddwaf_run(context2, &parameter1, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

    EXPECT_EQ(ddwaf_run(context1, &parameter2, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    EXPECT_EQ(ddwaf_run(context2, &parameter2, nullptr, nullptr, LONG_TIME), DDWAF_OK);

    ddwaf_object_free(&parameter1);
    ddwaf_object_free(&parameter2);

    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context1);
}

TEST(TestInterface, UpdateInvalidRules)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    rule = yaml_to_object("{rules: []}");
    ddwaf_handle new_handle = ddwaf_update(handle, &rule, nullptr);
    ASSERT_EQ(new_handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_destroy(handle);
}

TEST(TestInterface, UpdateDisableEnableRuleByID)
{
    auto rule = read_file("interface.yaml");
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
            yaml_to_object(R"({rules_override: [{rules_target: [{rule_id: 1}], enabled: false}]})");
        handle2 = ddwaf_update(handle1, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    ddwaf_object tmp;
    ddwaf_object parameter1 = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter1, "value1", ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object parameter2 = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter2, "value1", ddwaf_object_string(&tmp, "rule2"));

    EXPECT_EQ(ddwaf_run(context1, &parameter1, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    EXPECT_EQ(ddwaf_run(context2, &parameter1, nullptr, nullptr, LONG_TIME), DDWAF_OK);

    EXPECT_EQ(ddwaf_run(context1, &parameter2, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    EXPECT_EQ(ddwaf_run(context2, &parameter2, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

    ddwaf_object_free(&parameter1);
    ddwaf_object_free(&parameter2);

    ddwaf_context_destroy(context1);
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto overrides = yaml_to_object(R"({rules_override: []})");
        handle3 = ddwaf_update(handle2, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    ddwaf_context context3 = ddwaf_context_init(handle3);
    ASSERT_NE(context3, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateDisableEnableRuleByTags)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_handle handle2;
    {
        auto overrides = yaml_to_object(
            R"({rules_override: [{rules_target: [{tags: {type: flow2}}], enabled: false}]})");
        handle2 = ddwaf_update(handle1, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object parameter1 = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter1, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object parameter2 = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter2, "value1", ddwaf_object_string(&tmp, "rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter1, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter1, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_run(context1, &parameter2, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter2, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter1);
        ddwaf_object_free(&parameter2);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto overrides = yaml_to_object(R"({rules_override: []})");
        handle3 = ddwaf_update(handle2, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    ddwaf_context context3 = ddwaf_context_init(handle3);
    ASSERT_NE(context3, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object parameter1 = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter1, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object parameter2 = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter2, "value1", ddwaf_object_string(&tmp, "rule2"));

        EXPECT_EQ(ddwaf_run(context2, &parameter1, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter1, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_run(context2, &parameter2, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter2, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter1);
        ddwaf_object_free(&parameter2);
    }

    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateActionsByID)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto overrides = yaml_to_object(
            R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [block]}]})");
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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result1.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result2.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result2.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result2.actions, 0), nullptr), "block");

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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result1.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result2.actions), 0);

        ddwaf_result_free(&result1);
        ddwaf_result_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto overrides = yaml_to_object(
            R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [redirect]}], actions: [{id: redirect, type: redirect_request, parameters: {}}]})");
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

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result2.actions), 1);
        EXPECT_EQ(ddwaf_object_size(&result3.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result2.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result2.actions, 0), nullptr), "block");
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result3.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(ddwaf_object_get_string(ddwaf_object_get_index(&result3.actions, 0), nullptr),
            "redirect");

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
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto overrides = yaml_to_object(
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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result1.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result2.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result2.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result2.actions, 0), nullptr), "block");

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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result1.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result2.actions), 0);

        ddwaf_result_free(&result1);
        ddwaf_result_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
}

TEST(TestInterface, UpdateOverrideByIDAndTag)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto overrides = yaml_to_object(
            R"({rules_override: [{rules_target: [{tags: {type: flow1}}], on_match: ["block"], enabled: false}, {rules_target: [{rule_id: 1}], enabled: true}]})");
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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_size(&result1.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result2.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result2.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result2.actions, 0), nullptr), "block");

        ddwaf_result_free(&result1);
        ddwaf_result_free(&result2);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context1);
        ddwaf_context_destroy(context2);
    }

    ddwaf_handle handle3;
    {
        auto overrides = yaml_to_object(
            R"({rules_override: [{rules_target: [{tags: {type: flow1}}], on_match: ["block"]}, {rules_target: [{rule_id: 1}], on_match: []}]})");
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

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_size(&result2.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result2.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result2.actions, 0), nullptr), "block");
        EXPECT_EQ(ddwaf_object_size(&result3.actions), 0);

        ddwaf_result_free(&result2);
        ddwaf_result_free(&result3);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context3);
    }

    ddwaf_handle handle4;
    {
        auto overrides = yaml_to_object(
            R"({rules_override: [{rules_target: [{tags: {type: flow1}}], enabled: true}, {rules_target: [{rule_id: 1}], enabled: false}]})");
        handle4 = ddwaf_update(handle3, &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    {
        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_context context4 = ddwaf_context_init(handle4);
        ASSERT_NE(context4, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context4, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context3);
        ddwaf_context_destroy(context4);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
    ddwaf_destroy(handle4);
}

TEST(TestInterface, UpdateInvalidOverrides)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto overrides = yaml_to_object(R"({rules_override: [{enabled: false}]})");
    ddwaf_handle handle2 = ddwaf_update(handle1, &overrides, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&overrides);

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
}

TEST(TestInterface, UpdateRuleData)
{
    auto rule = read_file("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto data = yaml_to_object(
            R"({rules_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 0}]}]})");
        handle2 = ddwaf_update(handle1, &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_handle handle3;
    {
        auto data = yaml_to_object(
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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateAndRevertRuleData)
{
    auto rule = read_file("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto data = yaml_to_object(
            R"({rules_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 0}]}]})");
        handle2 = ddwaf_update(handle1, &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_object tmp;
    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context1);
        ddwaf_context_destroy(context2);
    }

    ddwaf_handle handle3;
    {
        auto data = yaml_to_object(R"({rules_data: []})");
        handle3 = ddwaf_update(handle2, &data, nullptr);
        ddwaf_object_free(&data);
    }

    {
        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context3);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateInvalidRuleData)
{
    auto rule = read_file("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    // A rules_data with unrelated keys is considered an empty rules_data
    auto data = yaml_to_object(
        R"({rules_data: [{id: ipo_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 0}]}]})");
    ddwaf_handle handle2 = ddwaf_update(handle1, &data, nullptr);
    EXPECT_NE(handle2, nullptr);
    ddwaf_object_free(&data);

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
}

TEST(TestInterface, UpdateRuleExclusions)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto exclusions =
            yaml_to_object(R"({exclusions: [{id: 1, rules_target: [{rule_id: 1}]}]})");
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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto exclusions = yaml_to_object(R"({exclusions: []})");
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

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context3);
        ddwaf_context_destroy(context2);
    }

    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateInputExclusions)
{
    auto rule = read_file("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle2;
    {
        auto exclusions = yaml_to_object(R"({exclusions: [{id: 1, inputs: [{address: value1}]}]})");
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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto exclusions = yaml_to_object(R"({exclusions: []})");
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

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context3);
        ddwaf_context_destroy(context2);
    }

    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);
}

TEST(TestInterface, UpdateEverything)
{
    auto rule = read_file("interface_with_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    // After this update:
    //   - No rule will match server.request.query
    ddwaf_handle handle2;
    {
        auto exclusions =
            yaml_to_object(R"({exclusions: [{id: 1, inputs: [{address: server.request.query}]}]})");
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
        ddwaf_object_map_add(
            &parameter, "server.request.query", ddwaf_object_string(&tmp, "rule3"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

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
        ddwaf_object_map_add(
            &parameter, "server.request.params", ddwaf_object_string(&tmp, "rule4"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    // After this update:
    //   - No rule will match server.request.query
    //   - Rules with confidence=1 will provide a block action
    ddwaf_handle handle3;
    {
        auto overrides = yaml_to_object(
            R"({rules_override: [{rules_target: [{tags: {confidence: 1}}], on_match: [block]}]})");
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
        ddwaf_object_map_add(
            &parameter, "server.response.status", ddwaf_object_string(&tmp, "rule5"));

        ddwaf_result result2;
        ddwaf_result result3;

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result2.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result3.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result3.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result3.actions, 0), nullptr), "block");

        ddwaf_result_free(&result2);
        ddwaf_result_free(&result3);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context3);
    }

    {
        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "server.request.query", ddwaf_object_string(&tmp, "rule3"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context3);
    }

    // After this update:
    //   - No rule will match server.request.query
    //   - Rules with confidence=1 will provide a block action
    //   - Rules with ip_data or usr_data will now match
    ddwaf_handle handle4;
    {
        auto data = yaml_to_object(
            R"({rules_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 0}]},{id: usr_data, type: data_with_expiration, data: [{value: admin, expiration 0}]}]})");
        handle4 = ddwaf_update(handle3, &data, nullptr);
        ddwaf_object_free(&data);
    }

    ASSERT_NE(handle4, nullptr);

    {
        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_context context4 = ddwaf_context_init(handle4);
        ASSERT_NE(context4, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        ddwaf_result result3;
        ddwaf_result result4;

        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context4, &parameter, nullptr, &result4, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result3.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result4.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result4.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result4.actions, 0), nullptr), "block");

        ddwaf_result_free(&result3);
        ddwaf_result_free(&result4);

        ddwaf_context_destroy(context3);
        ddwaf_context_destroy(context4);
    }

    {
        ddwaf_context context4 = ddwaf_context_init(handle4);
        ASSERT_NE(context4, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "server.request.query", ddwaf_object_string(&tmp, "rule3"));

        EXPECT_EQ(ddwaf_run(context4, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context4);
    }

    // After this update:
    //   - No rule will match server.request.query
    //   - Rules with confidence=1 will provide a block action
    //   - Rules with ip_data or usr_data will now match
    //   - The following rules will be removed: rule3, rule4, rule5
    ddwaf_handle handle5;
    {
        auto data = read_file("rule_data.yaml");
        handle5 = ddwaf_update(handle4, &data, nullptr);
        ddwaf_object_free(&data);
    }

    ASSERT_NE(handle5, nullptr);

    {
        ddwaf_context context4 = ddwaf_context_init(handle4);
        ASSERT_NE(context4, nullptr);

        ddwaf_context context5 = ddwaf_context_init(handle5);
        ASSERT_NE(context5, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        ddwaf_result result4;
        ddwaf_result result5;

        EXPECT_EQ(ddwaf_run(context4, &parameter, nullptr, &result4, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context5, &parameter, nullptr, &result5, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result4.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result4.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result4.actions, 0), nullptr), "block");
        EXPECT_EQ(ddwaf_object_size(&result5.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result5.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result5.actions, 0), nullptr), "block");

        ddwaf_result_free(&result4);
        ddwaf_result_free(&result5);

        ddwaf_context_destroy(context4);
        ddwaf_context_destroy(context5);
    }

    {
        ddwaf_context context4 = ddwaf_context_init(handle4);
        ASSERT_NE(context4, nullptr);

        ddwaf_context context5 = ddwaf_context_init(handle5);
        ASSERT_NE(context5, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "usr.id", ddwaf_object_string(&tmp, "admin"));

        EXPECT_EQ(ddwaf_run(context4, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context5, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context4);
        ddwaf_context_destroy(context5);
    }

    {
        ddwaf_context context4 = ddwaf_context_init(handle4);
        ASSERT_NE(context4, nullptr);

        ddwaf_context context5 = ddwaf_context_init(handle5);
        ASSERT_NE(context5, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "server.response.status", ddwaf_object_string(&tmp, "rule5"));

        ddwaf_result result4;
        ddwaf_result result5;

        EXPECT_EQ(ddwaf_run(context4, &parameter, nullptr, &result4, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context5, &parameter, nullptr, &result5, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result4.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result4.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result4.actions, 0), nullptr), "block");
        EXPECT_EQ(ddwaf_object_size(&result5.actions), 0);

        ddwaf_result_free(&result4);
        ddwaf_result_free(&result5);

        ddwaf_context_destroy(context4);
        ddwaf_context_destroy(context5);
    }

    // After this update:
    //   - No rule will match server.request.query
    //   - Rules with confidence=1 will provide a block action
    //   - Rules with ip_data or usr_data will now match
    //   - The following rules be back: rule3, rule4, rule5
    ddwaf_handle handle6;
    {
        auto data = read_file("interface_with_data.yaml");
        handle6 = ddwaf_update(handle5, &data, nullptr);
        ddwaf_object_free(&data);
    }

    ASSERT_NE(handle6, nullptr);

    {
        ddwaf_context context5 = ddwaf_context_init(handle5);
        ASSERT_NE(context5, nullptr);

        ddwaf_context context6 = ddwaf_context_init(handle6);
        ASSERT_NE(context6, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "server.response.status", ddwaf_object_string(&tmp, "rule5"));

        ddwaf_result result5;
        ddwaf_result result6;

        EXPECT_EQ(ddwaf_run(context5, &parameter, nullptr, &result5, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context6, &parameter, nullptr, &result6, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result5.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result6.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result6.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result6.actions, 0), nullptr), "block");

        ddwaf_result_free(&result5);
        ddwaf_result_free(&result6);

        ddwaf_context_destroy(context5);
        ddwaf_context_destroy(context6);
    }

    {
        ddwaf_context context5 = ddwaf_context_init(handle5);
        ASSERT_NE(context5, nullptr);

        ddwaf_context context6 = ddwaf_context_init(handle6);
        ASSERT_NE(context6, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        ddwaf_result result5;
        ddwaf_result result6;

        EXPECT_EQ(ddwaf_run(context5, &parameter, nullptr, &result5, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context6, &parameter, nullptr, &result6, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result5.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result5.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result5.actions, 0), nullptr), "block");
        EXPECT_EQ(ddwaf_object_size(&result6.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result6.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result6.actions, 0), nullptr), "block");

        ddwaf_result_free(&result5);
        ddwaf_result_free(&result6);

        ddwaf_context_destroy(context5);
        ddwaf_context_destroy(context6);
    }

    {
        ddwaf_context context6 = ddwaf_context_init(handle6);
        ASSERT_NE(context6, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "server.request.query", ddwaf_object_string(&tmp, "rule3"));

        EXPECT_EQ(ddwaf_run(context6, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context6);
    }

    // After this update:
    //   - Rules with confidence=1 will provide a block action
    //   - Rules with ip_data or usr_data will now match
    ddwaf_handle handle7;
    {
        auto exclusions = yaml_to_object(R"({exclusions: []})");
        handle7 = ddwaf_update(handle6, &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    ASSERT_NE(handle7, nullptr);

    {
        ddwaf_context context6 = ddwaf_context_init(handle6);
        ASSERT_NE(context6, nullptr);

        ddwaf_context context7 = ddwaf_context_init(handle7);
        ASSERT_NE(context7, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "server.request.query", ddwaf_object_string(&tmp, "rule3"));

        ddwaf_result result6;
        ddwaf_result result7;

        EXPECT_EQ(ddwaf_run(context6, &parameter, nullptr, &result6, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context7, &parameter, nullptr, &result7, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result6.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result7.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result7.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result7.actions, 0), nullptr), "block");

        ddwaf_result_free(&result6);
        ddwaf_result_free(&result7);

        ddwaf_context_destroy(context6);
        ddwaf_context_destroy(context7);
    }

    // After this update:
    //   - Rules with ip_data or usr_data will now match
    ddwaf_handle handle8;
    {
        auto exclusions = yaml_to_object(R"({rules_override: []})");
        handle8 = ddwaf_update(handle7, &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    ASSERT_NE(handle8, nullptr);

    {
        ddwaf_context context7 = ddwaf_context_init(handle7);
        ASSERT_NE(context7, nullptr);

        ddwaf_context context8 = ddwaf_context_init(handle8);
        ASSERT_NE(context8, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "server.request.query", ddwaf_object_string(&tmp, "rule3"));

        ddwaf_result result7;
        ddwaf_result result8;

        EXPECT_EQ(ddwaf_run(context7, &parameter, nullptr, &result7, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context8, &parameter, nullptr, &result8, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result7.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result7.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result7.actions, 0), nullptr), "block");
        EXPECT_EQ(ddwaf_object_size(&result8.actions), 0);

        ddwaf_result_free(&result7);
        ddwaf_result_free(&result8);

        ddwaf_context_destroy(context7);
        ddwaf_context_destroy(context8);
    }

    {
        ddwaf_context context7 = ddwaf_context_init(handle7);
        ASSERT_NE(context7, nullptr);

        ddwaf_context context8 = ddwaf_context_init(handle8);
        ASSERT_NE(context8, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        ddwaf_result result7;
        ddwaf_result result8;

        EXPECT_EQ(ddwaf_run(context7, &parameter, nullptr, &result7, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context8, &parameter, nullptr, &result8, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result7.actions), 1);
        EXPECT_EQ(ddwaf_object_type(ddwaf_object_get_index(&result7.actions, 0)), DDWAF_OBJ_STRING);
        EXPECT_STREQ(
            ddwaf_object_get_string(ddwaf_object_get_index(&result7.actions, 0), nullptr), "block");
        EXPECT_EQ(ddwaf_object_size(&result8.actions), 0);

        ddwaf_result_free(&result7);
        ddwaf_result_free(&result8);

        ddwaf_context_destroy(context7);
        ddwaf_context_destroy(context8);
    }

    // After this update, back to the original behaviour
    ddwaf_handle handle9;
    {
        auto exclusions = yaml_to_object(R"({rules_data: []})");
        handle9 = ddwaf_update(handle8, &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    ASSERT_NE(handle9, nullptr);

    {
        ddwaf_context context8 = ddwaf_context_init(handle8);
        ASSERT_NE(context8, nullptr);

        ddwaf_context context9 = ddwaf_context_init(handle9);
        ASSERT_NE(context9, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "server.request.query", ddwaf_object_string(&tmp, "rule3"));

        ddwaf_result result8;
        ddwaf_result result9;

        EXPECT_EQ(ddwaf_run(context8, &parameter, nullptr, &result8, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context9, &parameter, nullptr, &result9, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result8.actions), 0);
        EXPECT_EQ(ddwaf_object_size(&result9.actions), 0);

        ddwaf_result_free(&result8);
        ddwaf_result_free(&result9);

        ddwaf_context_destroy(context8);
        ddwaf_context_destroy(context9);
    }

    {
        ddwaf_context context8 = ddwaf_context_init(handle8);
        ASSERT_NE(context8, nullptr);

        ddwaf_context context9 = ddwaf_context_init(handle9);
        ASSERT_NE(context9, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        ddwaf_result result8;
        ddwaf_result result9;

        EXPECT_EQ(ddwaf_run(context8, &parameter, nullptr, &result8, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context9, &parameter, nullptr, &result9, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        EXPECT_EQ(ddwaf_object_size(&result9.actions), 0);

        ddwaf_result_free(&result8);
        ddwaf_result_free(&result9);

        ddwaf_context_destroy(context8);
        ddwaf_context_destroy(context9);
    }

    for (auto *handle : {handle1, handle2, handle3, handle4, handle6, handle7, handle8, handle9}) {
        uint32_t size;
        const char *const *addresses = ddwaf_known_addresses(handle, &size);
        EXPECT_EQ(size, 4);

        std::set<std::string_view> available_addresses{"http.client_ip", "server.request.query",
            "server.request.params", "server.response.status"};
        while ((size--) != 0U) {
            EXPECT_NE(available_addresses.find(addresses[size]), available_addresses.end());
        }
    }

    for (auto *handle : {handle5}) {
        uint32_t size;
        const char *const *addresses = ddwaf_known_addresses(handle, &size);
        EXPECT_EQ(size, 3);

        // While the ruleset contains 2 addresses, an existing object filter
        // forces server.request.query to be kept
        std::set<std::string_view> available_addresses{
            "http.client_ip", "usr.id", "server.request.query"};
        while ((size--) != 0U) {
            EXPECT_NE(available_addresses.find(addresses[size]), available_addresses.end());
        }
    }

    ddwaf_destroy(handle9);
    ddwaf_destroy(handle8);
    ddwaf_destroy(handle7);
    ddwaf_destroy(handle6);
    ddwaf_destroy(handle5);
    ddwaf_destroy(handle4);
    ddwaf_destroy(handle3);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle1);
}

} // namespace
