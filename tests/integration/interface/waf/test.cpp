// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"
#include "version.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

constexpr std::string_view base_dir = "integration/interface/waf/";

TEST(TestWafIntegration, Empty)
{
    auto rule = yaml_to_object<ddwaf_object>("{}");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);
}

TEST(TestWafIntegration, GetWafVersion)
{
    EXPECT_STREQ(ddwaf_get_version(), ddwaf::current_version.cstring());
}

TEST(TestWafIntegration, HandleBad)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, ddwaf_object_free};

    ddwaf_object tmp;
    ddwaf_object object = DDWAF_OBJECT_INVALID;
    EXPECT_EQ(ddwaf_init(&object, &config, nullptr), nullptr);

    EXPECT_NO_FATAL_FAILURE(ddwaf_destroy(nullptr));

    ddwaf_object_string(&object, "value");
    EXPECT_EQ(ddwaf_run(nullptr, &object, nullptr, nullptr, 1), DDWAF_ERR_INVALID_ARGUMENT);
    ddwaf_object_free(&object);

    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
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
    ddwaf_object res;
    EXPECT_EQ(ddwaf_run(context, &object, nullptr, &res, 0), DDWAF_OK);

    const auto *timeout = ddwaf_object_find(&res, STRL("timeout"));
    EXPECT_TRUE(ddwaf_object_get_bool(timeout));

    ddwaf_object_free(&res);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestWafIntegration, RootAddresses)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};

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

TEST(TestWafIntegration, HandleLifetime)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

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

    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

    ddwaf_object_free(&parameter);
    ddwaf_context_destroy(context);
}

TEST(TestWafIntegration, HandleLifetimeMultipleContexts)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};

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

TEST(TestWafIntegration, InvalidVersion)
{
    auto rule = yaml_to_object<ddwaf_object>("{version: 3.0, rules: []}");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_EQ(handle1, nullptr);
    ddwaf_object_free(&rule);
}

TEST(TestWafIntegration, InvalidVersionNoRules)
{
    auto rule = yaml_to_object<ddwaf_object>("{version: 3.0}");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_EQ(handle1, nullptr);
    ddwaf_object_free(&rule);
}

TEST(TestWafIntegration, PreloadRuleData)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    {
        auto rule = read_file<ddwaf_object>("rules_requiring_data.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &rule, nullptr);
        ddwaf_object_free(&rule);

        auto rule_data = read_file<ddwaf_object>("rule_data.yaml", base_dir);
        ASSERT_TRUE(rule_data.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rule_data"), &rule_data, nullptr);
        ddwaf_object_free(&rule_data);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

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
        auto rule_data = yaml_to_object<ddwaf_object>(
            R"({rules_data: [{id: usr_data, type: data_with_expiration, data: [{value: pepe, expiration: 0}]}, {id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.2, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rule_data"), &rule_data, nullptr);
        ddwaf_object_free(&rule_data);

        ddwaf_handle new_handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(new_handle, nullptr);
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
    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateRules)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};

    ddwaf_builder builder = ddwaf_builder_init(&config);
    ddwaf_builder_add_or_update_config(builder, "default", sizeof("default") - 1, &rule, nullptr);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    ddwaf_builder_remove_config(builder, "default", sizeof("default") - 1);

    rule = read_file<ddwaf_object>("interface3.yaml", base_dir);
    ddwaf_builder_add_or_update_config(
        builder, "new_config", sizeof("new_config") - 1, &rule, nullptr);
    ddwaf_handle new_handle = ddwaf_builder_build_instance(builder);
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

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateDisableEnableRuleByID)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);
    ASSERT_NE(builder, nullptr);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("interface"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 1}], enabled: false}]})");
        ASSERT_TRUE(overrides.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }
    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

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

    ddwaf_builder_remove_config(builder, LSTRARG("overrides"));
    auto *handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

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

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateDisableEnableRuleByTags)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{tags: {type: flow2}}], enabled: false}]})");
        ASSERT_TRUE(overrides.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }
    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

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

    ddwaf_builder_remove_config(builder, LSTRARG("overrides"));
    auto *handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

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

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateActionsByID)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);
    ASSERT_NE(builder, nullptr);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        uint32_t actions_size;
        const char *const *actions = ddwaf_known_actions(handle1, &actions_size);
        EXPECT_EQ(actions_size, 0);
        EXPECT_EQ(actions, nullptr);
    }

    ddwaf_handle handle2;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [block]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle2 = ddwaf_builder_build_instance(builder);

        uint32_t actions_size;
        const char *const *actions = ddwaf_known_actions(handle2, &actions_size);
        EXPECT_EQ(actions_size, 1);
        ASSERT_NE(actions, nullptr);
        EXPECT_STREQ(actions[0], "block_request");
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object result1;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result1, {});
        EXPECT_ACTIONS(
            result2, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});

        ddwaf_object_free(&result1);
        ddwaf_object_free(&result2);

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

        ddwaf_object result1;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result1, {});
        EXPECT_ACTIONS(result2, {});

        ddwaf_object_free(&result1);
        ddwaf_object_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }
    ddwaf_destroy(handle1);

    ddwaf_handle handle3;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [redirect]}], actions: [{id: redirect, type: redirect_request, parameters: {location: http://google.com, status_code: 303}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle3 = ddwaf_builder_build_instance(builder);

        uint32_t actions_size;
        const char *const *actions = ddwaf_known_actions(handle3, &actions_size);
        EXPECT_EQ(actions_size, 1);
        ASSERT_NE(actions, nullptr);
        EXPECT_STREQ(actions[0], "redirect_request");
    }

    {
        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object result2;
        ddwaf_object result3;

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(
            result2, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});
        EXPECT_ACTIONS(result3,
            {{"redirect_request", {{"status_code", "303"}, {"location", "http://google.com"}}}});

        ddwaf_object_free(&result2);
        ddwaf_object_free(&result3);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context3);
    }

    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateActionsByTags)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        uint32_t actions_size;
        const char *const *actions = ddwaf_known_actions(handle1, &actions_size);
        EXPECT_EQ(actions_size, 0);
        EXPECT_EQ(actions, nullptr);
    }

    ddwaf_handle handle2;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{tags: {confidence: 1}}], on_match: [block]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle2 = ddwaf_builder_build_instance(builder);

        uint32_t actions_size;
        const char *const *actions = ddwaf_known_actions(handle2, &actions_size);
        EXPECT_EQ(actions_size, 1);
        ASSERT_NE(actions, nullptr);
        EXPECT_STREQ(actions[0], "block_request");
    }

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object result1;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result1, {});
        EXPECT_ACTIONS(
            result2, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});

        ddwaf_object_free(&result1);
        ddwaf_object_free(&result2);

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

        ddwaf_object result1;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result1, {});
        EXPECT_ACTIONS(result2, {});

        ddwaf_object_free(&result1);
        ddwaf_object_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateTagsByID)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 1}], tags: {category: new_category, confidence: 0, new_tag: value}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object result1;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(result1,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        EXPECT_EVENTS(result2,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"},
                    {"new_tag", "value"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        ddwaf_object_free(&parameter);

        ddwaf_object_free(&result1);
        ddwaf_object_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("overrides"));
    auto *handle3 = ddwaf_builder_build_instance(builder);

    {
        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object result3;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(result3,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        EXPECT_EVENTS(result2,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"},
                    {"new_tag", "value"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        ddwaf_object_free(&parameter);

        ddwaf_object_free(&result3);
        ddwaf_object_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context3);
    }

    ddwaf_destroy(handle2);
    ddwaf_destroy(handle1);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateTagsByTags)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{tags: {confidence: 1}}], tags: {new_tag: value, confidence: 0}}]})");
        ASSERT_TRUE(overrides.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object result1;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EVENTS(result1,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        EXPECT_EVENTS(result2,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"},
                    {"new_tag", "value"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        ddwaf_object_free(&result1);
        ddwaf_object_free(&result2);

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

        ddwaf_object result1;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EVENTS(result1,
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "flow2"}, {"category", "category2"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule2",
                    .highlight = "rule2"sv,
                    .args = {
                        {.name = "input", .value = "rule2"sv, .address = "value1", .path = {}}}}}});

        EXPECT_EVENTS(result2,
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "flow2"}, {"category", "category2"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule2",
                    .highlight = "rule2"sv,
                    .args = {
                        {.name = "input", .value = "rule2"sv, .address = "value1", .path = {}}}}}});

        ddwaf_object_free(&result1);
        ddwaf_object_free(&result2);

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

        ddwaf_object result1;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EVENTS(result1,
            {.id = "3",
                .name = "rule3",
                .tags = {{"type", "flow2"}, {"category", "category3"}, {"confidence", "1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule3",
                    .highlight = "rule3"sv,
                    .args = {
                        {.name = "input", .value = "rule3"sv, .address = "value2", .path = {}}}}}});

        EXPECT_EVENTS(result2,
            {.id = "3",
                .name = "rule3",
                .tags = {{"type", "flow2"}, {"category", "category3"}, {"confidence", "1"},
                    {"new_tag", "value"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule3",
                    .highlight = "rule3"sv,
                    .args = {
                        {.name = "input", .value = "rule3"sv, .address = "value2", .path = {}}}}}});

        ddwaf_object_free(&result1);
        ddwaf_object_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context1);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("overrides"));
    auto *handle3 = ddwaf_builder_build_instance(builder);

    {
        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2", ddwaf_object_string(&tmp, "rule3"));

        ddwaf_object result3;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_EVENTS(result3,
            {.id = "3",
                .name = "rule3",
                .tags = {{"type", "flow2"}, {"category", "category3"}, {"confidence", "1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule3",
                    .highlight = "rule3"sv,
                    .args = {
                        {.name = "input", .value = "rule3"sv, .address = "value2", .path = {}}}}}});

        EXPECT_EVENTS(result2,
            {.id = "3",
                .name = "rule3",
                .tags = {{"type", "flow2"}, {"category", "category3"}, {"confidence", "1"},
                    {"new_tag", "value"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule3",
                    .highlight = "rule3"sv,
                    .args = {
                        {.name = "input", .value = "rule3"sv, .address = "value2", .path = {}}}}}});
        ddwaf_object_free(&result3);
        ddwaf_object_free(&result2);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context3);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateOverrideByIDAndTag)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{tags: {type: flow1}}], tags: {new_tag: old_value}, on_match: ["block"], enabled: false}, {rules_target: [{rule_id: 1}], tags: {new_tag: new_value}, enabled: true}]})");
        ASSERT_TRUE(overrides.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context1 = ddwaf_context_init(handle1);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object result1;
        ddwaf_object result2;

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &result1, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(result1,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        EXPECT_EVENTS(result2,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"},
                    {"new_tag", "new_value"}},
                .actions = {"block"},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        EXPECT_ACTIONS(result1, {});
        EXPECT_ACTIONS(
            result2, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});

        ddwaf_object_free(&result1);
        ddwaf_object_free(&result2);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context1);
        ddwaf_context_destroy(context2);
    }

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{tags: {type: flow1}}], on_match: ["block"]}, {rules_target: [{rule_id: 1}], on_match: []}]})");
        ASSERT_TRUE(overrides.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    auto *handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object result2;
        ddwaf_object result3;

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(result2,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"},
                    {"new_tag", "new_value"}},
                .actions = {"block"},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        EXPECT_EVENTS(result3,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "rule1",
                    .highlight = "rule1"sv,
                    .args = {
                        {.name = "input", .value = "rule1"sv, .address = "value1", .path = {}}}}}});

        EXPECT_ACTIONS(
            result2, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});
        EXPECT_ACTIONS(result3, {});

        ddwaf_object_free(&result2);
        ddwaf_object_free(&result3);

        ddwaf_object_free(&parameter);

        ddwaf_context_destroy(context2);
        ddwaf_context_destroy(context3);
    }

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{tags: {type: flow1}}], enabled: true}, {rules_target: [{rule_id: 1}], enabled: false}]})");
        ASSERT_TRUE(overrides.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    auto *handle4 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle4, nullptr);

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

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateInvalidOverrides)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    auto overrides = yaml_to_object<ddwaf_object>(R"({rules_override: [{enabled: false}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
    ddwaf_object_free(&overrides);

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateRuleData)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("rules_requiring_data.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto rule_data = yaml_to_object<ddwaf_object>(
            R"({rules_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rule_data"), &rule_data, nullptr);
        ddwaf_object_free(&rule_data);
    }

    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        auto rule_data = yaml_to_object<ddwaf_object>(
            R"({rules_data: [{id: usr_data, type: data_with_expiration, data: [{value: paco, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rule_data"), &rule_data, nullptr);
        ddwaf_object_free(&rule_data);
    }

    auto *handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

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

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateAndRevertRuleData)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("rules_requiring_data.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto rule_data = yaml_to_object<ddwaf_object>(
            R"({rules_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rule_data"), &rule_data, nullptr);
        ddwaf_object_free(&rule_data);
    }

    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

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

    ddwaf_builder_remove_config(builder, LSTRARG("rule_data"));
    auto *handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

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

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateRuleExclusions)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto exclusions = yaml_to_object<ddwaf_object>(
            R"({exclusions: [{id: 1, rules_target: [{rule_id: 1}]}]})");
        ASSERT_NE(exclusions.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusions"), &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

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

    ddwaf_builder_remove_config(builder, LSTRARG("exclusions"));
    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

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

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateInputExclusions)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto exclusions =
            yaml_to_object<ddwaf_object>(R"({exclusions: [{id: 1, inputs: [{address: value1}]}]})");
        ASSERT_NE(exclusions.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusions"), &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

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

    ddwaf_builder_remove_config(builder, LSTRARG("exclusions"));
    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

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

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, UpdateEverything)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("interface_with_data.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    // After this update:
    //   - No rule will match server.request.query
    {
        auto exclusions = yaml_to_object<ddwaf_object>(
            R"({exclusions: [{id: 1, inputs: [{address: server.request.query}]}]})");
        ASSERT_NE(exclusions.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusions"), &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

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
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{tags: {confidence: 1}}], on_match: [block]}]})");
        ASSERT_NE(overrides.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context2 = ddwaf_context_init(handle2);
        ASSERT_NE(context2, nullptr);

        ddwaf_context context3 = ddwaf_context_init(handle3);
        ASSERT_NE(context3, nullptr);

        ddwaf_object tmp;
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(
            &parameter, "server.response.status", ddwaf_object_string(&tmp, "rule5"));

        ddwaf_object result2;
        ddwaf_object result3;

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &result2, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result2, {});
        EXPECT_ACTIONS(
            result3, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});

        ddwaf_object_free(&result2);
        ddwaf_object_free(&result3);

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
    {
        auto data = yaml_to_object<ddwaf_object>(
            R"({rules_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 0}]},{id: usr_data, type: data_with_expiration, data: [{value: admin, expiration 0}]}]})");
        ASSERT_NE(data.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rule_data"), &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_handle handle4 = ddwaf_builder_build_instance(builder);
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

        ddwaf_object result3;
        ddwaf_object result4;

        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &result3, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context4, &parameter, nullptr, &result4, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result3, {});
        EXPECT_ACTIONS(
            result4, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});

        ddwaf_object_free(&result3);
        ddwaf_object_free(&result4);

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
    {
        auto rule = read_file<ddwaf_object>("rules_requiring_data.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle5 = ddwaf_builder_build_instance(builder);
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

        ddwaf_object result4;
        ddwaf_object result5;

        EXPECT_EQ(ddwaf_run(context4, &parameter, nullptr, &result4, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context5, &parameter, nullptr, &result5, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(
            result4, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});
        EXPECT_ACTIONS(
            result5, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});

        ddwaf_object_free(&result4);
        ddwaf_object_free(&result5);

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

        ddwaf_object result4;
        ddwaf_object result5;

        EXPECT_EQ(ddwaf_run(context4, &parameter, nullptr, &result4, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context5, &parameter, nullptr, &result5, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(
            result4, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});
        EXPECT_ACTIONS(result5, {});

        ddwaf_object_free(&result4);
        ddwaf_object_free(&result5);

        ddwaf_context_destroy(context4);
        ddwaf_context_destroy(context5);
    }

    // After this update:
    //   - No rule will match server.request.query
    //   - Rules with confidence=1 will provide a block action
    //   - Rules with ip_data or usr_data will now match
    //   - The following rules be back: rule3, rule4, rule5
    {
        auto rule = read_file<ddwaf_object>("interface_with_data.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle6 = ddwaf_builder_build_instance(builder);
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

        ddwaf_object result5;
        ddwaf_object result6;

        EXPECT_EQ(ddwaf_run(context5, &parameter, nullptr, &result5, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context6, &parameter, nullptr, &result6, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result5, {});
        EXPECT_ACTIONS(
            result6, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});

        ddwaf_object_free(&result5);
        ddwaf_object_free(&result6);

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

        ddwaf_object result5;
        ddwaf_object result6;

        EXPECT_EQ(ddwaf_run(context5, &parameter, nullptr, &result5, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context6, &parameter, nullptr, &result6, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(
            result5, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});
        EXPECT_ACTIONS(
            result6, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});

        ddwaf_object_free(&result5);
        ddwaf_object_free(&result6);

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
    ddwaf_builder_remove_config(builder, LSTRARG("exclusions"));
    ddwaf_handle handle7 = ddwaf_builder_build_instance(builder);
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

        ddwaf_object result6;
        ddwaf_object result7;

        EXPECT_EQ(ddwaf_run(context6, &parameter, nullptr, &result6, LONG_TIME), DDWAF_OK);
        EXPECT_EQ(ddwaf_run(context7, &parameter, nullptr, &result7, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result6, {});
        EXPECT_ACTIONS(
            result7, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});

        ddwaf_object_free(&result6);
        ddwaf_object_free(&result7);

        ddwaf_context_destroy(context6);
        ddwaf_context_destroy(context7);
    }

    // After this update:
    //   - Rules with ip_data or usr_data will now match
    ddwaf_builder_remove_config(builder, LSTRARG("overrides"));
    ddwaf_handle handle8 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle8, nullptr);

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

        ddwaf_object result7;
        ddwaf_object result8;

        EXPECT_EQ(ddwaf_run(context7, &parameter, nullptr, &result7, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context8, &parameter, nullptr, &result8, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(
            result7, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});
        EXPECT_ACTIONS(result8, {});

        ddwaf_object_free(&result7);
        ddwaf_object_free(&result8);

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

        ddwaf_object result7;
        ddwaf_object result8;

        EXPECT_EQ(ddwaf_run(context7, &parameter, nullptr, &result7, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context8, &parameter, nullptr, &result8, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(
            result7, {{"block_request",
                         {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}});
        EXPECT_ACTIONS(result8, {});

        ddwaf_object_free(&result7);
        ddwaf_object_free(&result8);

        ddwaf_context_destroy(context7);
        ddwaf_context_destroy(context8);
    }

    // After this update, back to the original behaviour
    ddwaf_builder_remove_config(builder, LSTRARG("rule_data"));
    ddwaf_handle handle9 = ddwaf_builder_build_instance(builder);
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

        ddwaf_object result8;
        ddwaf_object result9;

        EXPECT_EQ(ddwaf_run(context8, &parameter, nullptr, &result8, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context9, &parameter, nullptr, &result9, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result8, {});
        EXPECT_ACTIONS(result9, {});

        ddwaf_object_free(&result8);
        ddwaf_object_free(&result9);

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

        ddwaf_object result8;
        ddwaf_object result9;

        EXPECT_EQ(ddwaf_run(context8, &parameter, nullptr, &result8, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_run(context9, &parameter, nullptr, &result9, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);

        EXPECT_ACTIONS(result9, {});

        ddwaf_object_free(&result8);
        ddwaf_object_free(&result9);

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

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, KnownAddressesDisabledRule)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("ruleset_with_disabled_rule.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("ruleset"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }
    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: id-rule-1}], enabled: true}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }
    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: id-rule-1}], enabled: false}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }
    auto *handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        uint32_t size;
        const auto *addresses = ddwaf_known_addresses(handle1, &size);
        std::set<std::string_view> available_addresses{"value2"};
        while ((size--) != 0U) {
            EXPECT_NE(available_addresses.find(addresses[size]), available_addresses.end());
        }
    }

    {
        uint32_t size;
        const auto *addresses = ddwaf_known_addresses(handle2, &size);

        std::set<std::string_view> available_addresses{"value1", "value2"};
        while ((size--) != 0U) {
            EXPECT_NE(available_addresses.find(addresses[size]), available_addresses.end());
        }
    }

    {
        uint32_t size;
        const auto *addresses = ddwaf_known_addresses(handle3, &size);
        std::set<std::string_view> available_addresses{"value2"};
        while ((size--) != 0U) {
            EXPECT_NE(available_addresses.find(addresses[size]), available_addresses.end());
        }
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, KnownActions)
{
    ddwaf_config config{{.key_regex = nullptr, .value_regex = nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle1, &size);
        EXPECT_EQ(size, 0);
        EXPECT_EQ(actions, nullptr);
    }

    // Add an action
    ddwaf_handle handle2;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [block]}]})");
        ASSERT_NE(overrides.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle2 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle2, &size);
        EXPECT_EQ(size, 1);
        ASSERT_NE(actions, nullptr);

        std::set<std::string_view> available_actions{"block_request"};
        while ((size--) != 0U) {
            EXPECT_NE(available_actions.find(actions[size]), available_actions.end());
        }

        ddwaf_destroy(handle1);
    }

    // Disable the rule containing the only action
    ddwaf_handle handle3;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 1}], enabled: false}]})");
        ASSERT_NE(overrides.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle3 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle3, &size);
        EXPECT_EQ(size, 0);
        EXPECT_EQ(actions, nullptr);

        ddwaf_destroy(handle2);
    }

    // Add a new action type and update another rule to use it
    ddwaf_handle handle4;
    {
        auto action_cfg = yaml_to_object<ddwaf_object>(
            R"({actions: [{id: redirect, type: redirect_request, parameters: {location: http://google.com, status_code: 303}}]})");
        ASSERT_NE(action_cfg.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("actions"), &action_cfg, nullptr);
        ddwaf_object_free(&action_cfg);

        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 2}], on_match: [redirect]}]})");
        ASSERT_NE(overrides.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle4 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle4, &size);
        EXPECT_EQ(size, 1);
        ASSERT_NE(actions, nullptr);

        std::set<std::string_view> available_actions{"redirect_request"};
        while ((size--) != 0U) {
            EXPECT_NE(available_actions.find(actions[size]), available_actions.end());
        }

        ddwaf_destroy(handle3);
    }

    // Add another action to a separate rule
    ddwaf_handle handle5;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [block]}, {rules_target: [{rule_id: 2}], on_match: [redirect]}]})");
        ASSERT_NE(overrides.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle5 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle5, &size);
        EXPECT_EQ(size, 2);
        ASSERT_NE(actions, nullptr);

        std::set<std::string_view> available_actions{"redirect_request", "block_request"};
        while ((size--) != 0U) {
            EXPECT_NE(available_actions.find(actions[size]), available_actions.end());
        }

        ddwaf_destroy(handle4);
    }

    // Add two actions to an existing rule
    ddwaf_handle handle6;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [block]}, {rules_target: [{rule_id: 2}], on_match: [redirect]}, {rules_target: [{rule_id: 3}], on_match: [block, stack_trace]}]})");
        ASSERT_NE(overrides.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle6 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle6, &size);
        EXPECT_EQ(size, 3);
        ASSERT_NE(actions, nullptr);

        std::set<std::string_view> available_actions{
            "redirect_request", "block_request", "generate_stack"};
        while ((size--) != 0U) {
            EXPECT_NE(available_actions.find(actions[size]), available_actions.end());
        }

        ddwaf_destroy(handle5);
    }

    // Remove the block action from rule1 and add an exclusion filter
    ddwaf_handle handle7;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 2}], on_match: [redirect]}, {rules_target: [{rule_id: 3}], on_match: [block, stack_trace]}]})");
        ASSERT_NE(overrides.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        auto exclusions = yaml_to_object<ddwaf_object>(
            R"({exclusions: [{id: 1, rules_target: [{rule_id: 1}], on_match: block}]})");
        ASSERT_NE(exclusions.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusions"), &exclusions, nullptr);
        ddwaf_object_free(&exclusions);

        handle7 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle7, &size);
        EXPECT_EQ(size, 3);
        ASSERT_NE(actions, nullptr);

        std::set<std::string_view> available_actions{
            "redirect_request", "block_request", "generate_stack"};
        while ((size--) != 0U) {
            EXPECT_NE(available_actions.find(actions[size]), available_actions.end());
        }

        ddwaf_destroy(handle6);
    }

    // Remove actions from all other rules
    ddwaf_handle handle8;
    {
        ddwaf_builder_remove_config(builder, LSTRARG("overrides"));

        handle8 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle8, &size);
        EXPECT_EQ(size, 1);
        ASSERT_NE(actions, nullptr);

        std::set<std::string_view> available_actions{"block_request"};
        while ((size--) != 0U) {
            EXPECT_NE(available_actions.find(actions[size]), available_actions.end());
        }

        ddwaf_destroy(handle7);
    }

    // Remove exclusions
    ddwaf_handle handle9;
    {
        ddwaf_builder_remove_config(builder, LSTRARG("exclusions"));

        handle9 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle9, &size);
        EXPECT_EQ(size, 0);
        ASSERT_EQ(actions, nullptr);

        ddwaf_destroy(handle8);
    }

    // Disable the rule containing the only action
    ddwaf_handle handle10;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: 1}], on_match: [whatever]}]})");
        ASSERT_NE(overrides.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle10 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle10, &size);
        EXPECT_EQ(size, 0);
        EXPECT_EQ(actions, nullptr);

        ddwaf_destroy(handle9);
    }

    // Add a custom rule with a custom action
    ddwaf_handle handle11;
    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({custom_rules:  [{id: u1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}], on_match: [random]}], actions: [{id: random, type: generate_schema, parameters: {}}]})");
        ASSERT_NE(overrides.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(
            builder, LSTRARG("custom_rules_and_actions"), &overrides, nullptr);
        ddwaf_object_free(&overrides);

        handle11 = ddwaf_builder_build_instance(builder);

        uint32_t size;
        const char *const *actions = ddwaf_known_actions(handle11, &size);
        EXPECT_EQ(size, 1);
        EXPECT_NE(actions, nullptr);
        std::set<std::string_view> available_actions{"generate_schema"};
        while ((size--) != 0U) {
            EXPECT_NE(available_actions.find(actions[size]), available_actions.end());
        }

        ddwaf_destroy(handle10);
    }

    ddwaf_destroy(handle11);
    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, KnownActionsNullHandle)
{
    uint32_t size;
    const char *const *actions = ddwaf_known_actions(nullptr, &size);
    EXPECT_EQ(size, 0);
    EXPECT_EQ(actions, nullptr);
}

std::unordered_set<std::string_view> object_to_string_set(const ddwaf_object *array)
{
    std::unordered_set<std::string_view> set;
    for (std::size_t i = 0; i < ddwaf_object_size(array); ++i) {
        const ddwaf_object *child = ddwaf_object_get_index(array, i);
        EXPECT_EQ(ddwaf_object_type(child), DDWAF_OBJ_STRING);
        set.emplace(child->stringValue, static_cast<std::size_t>(child->nbEntries));
    }
    return set;
}

TEST(TestWafIntegration, GetConfigPathSingleConfig)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init(nullptr);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM_DD/default"), &rule, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, nullptr, 0);

        EXPECT_EQ(count, 1);
        EXPECT_EQ(ddwaf_object_size(&paths), 1);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, nullptr, 0);
        EXPECT_EQ(count, 1);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, GetConfigPathMultipleConfigs)
{

    ddwaf_builder builder = ddwaf_builder_init(nullptr);
    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM_DD/default"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: id-rule-1}], enabled: false}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM/overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    {
        auto data = read_file<ddwaf_object>("rule_data.yaml", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM_DATA/blocked"), &data, nullptr);
        ddwaf_object_free(&data);
    }

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, nullptr, 0);

        EXPECT_EQ(count, 3);
        EXPECT_EQ(ddwaf_object_size(&paths), 3);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DATA/blocked"));
        EXPECT_TRUE(path_set.contains("ASM/overrides"));
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, nullptr, 0);
        EXPECT_EQ(count, 3);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("ASM/overrides"));
    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, nullptr, 0);

        EXPECT_EQ(count, 2);
        EXPECT_EQ(ddwaf_object_size(&paths), 2);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DATA/blocked"));
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, nullptr, 0);
        EXPECT_EQ(count, 2);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("ASM_DATA/blocked"));
    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, nullptr, 0);

        EXPECT_EQ(count, 1);
        EXPECT_EQ(ddwaf_object_size(&paths), 1);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, nullptr, 0);
        EXPECT_EQ(count, 1);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("ASM_DD/default"));
    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, nullptr, 0);

        EXPECT_EQ(count, 0);
        EXPECT_EQ(ddwaf_object_size(&paths), 0);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, nullptr, 0);
        EXPECT_EQ(count, 0);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, GetFilteredConfigPathSingleConfig)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init(nullptr);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM_DD/default"), &rule, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM_DD/.*"));
        EXPECT_EQ(count, 1);
        EXPECT_EQ(ddwaf_object_size(&paths), 1);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^ASM_DD/.*"));
        EXPECT_EQ(count, 1);
    }

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM/.*"));

        EXPECT_EQ(count, 0);
        EXPECT_EQ(ddwaf_object_size(&paths), 0);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^ASM/.*"));
        EXPECT_EQ(count, 0);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestWafIntegration, GetFilteredConfigPathMultipleConfigs)
{

    ddwaf_builder builder = ddwaf_builder_init(nullptr);
    {
        auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM_DD/default"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{rule_id: id-rule-1}], enabled: false}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM/overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    {
        auto data = read_file<ddwaf_object>("rule_data.yaml", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM_DATA/blocked"), &data, nullptr);
        ddwaf_object_free(&data);
    }

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^random"));

        EXPECT_EQ(count, 0);
        EXPECT_EQ(ddwaf_object_size(&paths), 0);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^random"));
        EXPECT_EQ(count, 0);
    }

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM.*"));

        EXPECT_EQ(count, 3);
        EXPECT_EQ(ddwaf_object_size(&paths), 3);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DATA/blocked"));
        EXPECT_TRUE(path_set.contains("ASM/overrides"));
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^ASM.*"));
        EXPECT_EQ(count, 3);
    }

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM_DD/.*"));

        EXPECT_EQ(count, 1);
        EXPECT_EQ(ddwaf_object_size(&paths), 1);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^ASM_DD/.*"));
        EXPECT_EQ(count, 1);
    }

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM_D.*"));

        EXPECT_EQ(count, 2);
        EXPECT_EQ(ddwaf_object_size(&paths), 2);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DATA/blocked"));
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^ASM_D.*"));
        EXPECT_EQ(count, 2);
    }

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM/.*"));

        EXPECT_EQ(count, 1);
        EXPECT_EQ(ddwaf_object_size(&paths), 1);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM/overrides"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^ASM/.*"));
        EXPECT_EQ(count, 1);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("ASM/overrides"));

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM_D.*"));

        EXPECT_EQ(count, 2);
        EXPECT_EQ(ddwaf_object_size(&paths), 2);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DATA/blocked"));
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^ASM_D.*"));
        EXPECT_EQ(count, 2);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("ASM_DATA/blocked"));
    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM_DD/.*"));

        EXPECT_EQ(count, 1);
        EXPECT_EQ(ddwaf_object_size(&paths), 1);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        auto path_set = object_to_string_set(&paths);
        EXPECT_TRUE(path_set.contains("ASM_DD/default"));

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^ASM_DD/.*"));
        EXPECT_EQ(count, 1);
    }

    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^random"));

        EXPECT_EQ(count, 0);
        EXPECT_EQ(ddwaf_object_size(&paths), 0);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^random"));
        EXPECT_EQ(count, 0);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("ASM_DD/default"));
    {
        ddwaf_object paths;
        auto count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM.*"));

        EXPECT_EQ(count, 0);
        EXPECT_EQ(ddwaf_object_size(&paths), 0);
        EXPECT_EQ(ddwaf_object_type(&paths), DDWAF_OBJ_ARRAY);

        ddwaf_object_free(&paths);
    }

    {
        auto count = ddwaf_builder_get_config_paths(builder, nullptr, LSTRARG("^ASM.*"));
        EXPECT_EQ(count, 0);
    }

    ddwaf_builder_destroy(builder);
}

} // namespace
