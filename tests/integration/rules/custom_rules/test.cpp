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
constexpr std::string_view base_dir = "integration/rules/custom_rules/";

// Custom rules can be used instead of base rules
TEST(TestCustomRulesIntegration, InitWithoutBaseRules)
{
    auto rule = read_file<ddwaf_object>("custom_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2", ddwaf_object_string(&tmp, "custom_rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    }

    ddwaf_context_destroy(context1);
}

// Custom rules can work alongside base rules
TEST(TestCustomRulesIntegration, InitWithBaseRules)
{
    auto rule = read_file<ddwaf_object>("custom_rules_and_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

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

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value2", ddwaf_object_string(&tmp, "custom_rule2"));

        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);
    }

    ddwaf_context_destroy(context1);
}

// Regular custom rules have precedence over regular base rules
TEST(TestCustomRulesIntegration, RegularCustomRulesPrecedence)
{
    auto rule = read_file<ddwaf_object>("custom_rules_and_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

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
        ddwaf_object_map_add(&parameter, "value3", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule3",
                               .name = "custom_rule3",
                               .tags = {{"type", "flow34"}, {"category", "category3"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value3"}}}}});
        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
}

// Priority custom rules have precedence over priority base rules
TEST(TestCustomRulesIntegration, PriorityCustomRulesPrecedence)
{
    auto rule = read_file<ddwaf_object>("custom_rules_and_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

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
        ddwaf_object_map_add(&parameter, "value4", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value4"}}}}});

        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
}

// Global rules precedence test Priority Custom > Priority Base > Custom > Base
TEST(TestCustomRulesIntegration, CustomRulesPrecedence)
{
    auto rule = read_file<ddwaf_object>("custom_rules_and_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

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
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
}

// Custom rules can be updated when base rules exist
TEST(TestCustomRulesIntegration, UpdateFromBaseRules)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("custom_rules_base_rules_only.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("base_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto rule = read_file<ddwaf_object>("custom_rules.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("custom_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .highlight = "rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);

    ddwaf_builder_destroy(builder);
}

// Custom rules can be updated when custom rules already exist
TEST(TestCustomRulesIntegration, UpdateFromCustomRules)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("custom_rules.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("custom_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto rule = yaml_to_object<ddwaf_object>(
            R"({custom_rules: [{id: custom_rule5, name: custom_rule5, tags: {type: flow5, category: category5}, conditions: [{operator: match_regex, parameters: {inputs: [{address: value34}], regex: custom_rule}}]}]})");
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("custom_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule5",
                               .name = "custom_rule5",
                               .tags = {{"type", "flow5"}, {"category", "category5"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});

        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);

    ddwaf_builder_destroy(builder);
}

// Remove all custom rules when no other rules are available
TEST(TestCustomRulesIntegration, UpdateWithEmptyRules)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    auto rule = read_file<ddwaf_object>("custom_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("custom_rules"), &rule, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    ddwaf_builder_remove_config(builder, LSTRARG("custom_rules"));
    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle1);

    ddwaf_builder_destroy(builder);
}

// Remove all custom rules when base rules are available
TEST(TestCustomRulesIntegration, UpdateRemoveAllCustomRules)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("custom_rules_base_rules_only.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("base_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    {
        auto rule = read_file<ddwaf_object>("custom_rules.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("custom_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }
    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    ddwaf_builder_remove_config(builder, LSTRARG("custom_rules"));
    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .highlight = "rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);

    ddwaf_builder_destroy(builder);
}

// Ensure that existing custom rules are unaffected by overrides
TEST(TestCustomRulesIntegration, CustomRulesUnaffectedByOverrides)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("custom_rules.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("custom_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{tags: {category: category4}}], enabled: false}]})");
        ASSERT_TRUE(overrides.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);

    ddwaf_builder_destroy(builder);
}

// Ensure that custom rules are unaffected by overrides after an update
TEST(TestCustomRulesIntegration, CustomRulesUnaffectedByOverridesAfterUpdate)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("custom_rules_base_rules_only.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("base_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto overrides = yaml_to_object<ddwaf_object>(
            R"({rules_override: [{rules_target: [{tags: {category: category4}}], enabled: false}]})");
        ASSERT_TRUE(overrides.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("overrides"), &overrides, nullptr);
        ddwaf_object_free(&overrides);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        auto rule = read_file<ddwaf_object>("custom_rules.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("custom_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    ddwaf_context context3 = ddwaf_context_init(handle3);
    ASSERT_NE(context3, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value4", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .highlight = "rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value4"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value4", ddwaf_object_string(&tmp, "custom_rule"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, nullptr, LONG_TIME), DDWAF_OK);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value4", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value4"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);

    ddwaf_builder_destroy(builder);
}

// Ensure that existing custom rules are unaffected by overrides
TEST(TestCustomRulesIntegration, CustomRulesAffectedByExclusions)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("custom_rules_and_rules.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto exclusions = yaml_to_object<ddwaf_object>(
            R"({exclusions: [{id: custom_rule4_exclude, rules_target: [{rule_id: custom_rule4}]}]})");
        ASSERT_TRUE(exclusions.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusions"), &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .highlight = "rule"sv,
                                   .args = {{.value = "custom_rule"sv, .address = "value34"}}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);

    ddwaf_builder_destroy(builder);
}

// Ensure that custom rules are affected by overrides after an update
TEST(TestCustomRulesIntegration, CustomRulesAffectedByExclusionsAfterUpdate)
{
    ddwaf_config config{{nullptr, nullptr}, nullptr};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    {
        auto rule = read_file<ddwaf_object>("custom_rules_base_rules_only.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("base_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto exclusions = yaml_to_object<ddwaf_object>(
            R"({exclusions: [{id: custom_rule4_exclude, rules_target: [{tags: {category: category4}}]}]})");
        ASSERT_TRUE(exclusions.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusions"), &exclusions, nullptr);
        ddwaf_object_free(&exclusions);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        auto rule = read_file<ddwaf_object>("custom_rules.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("custom_rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    ddwaf_context context1 = ddwaf_context_init(handle1);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle2);
    ASSERT_NE(context2, nullptr);

    ddwaf_context context3 = ddwaf_context_init(handle3);
    ASSERT_NE(context3, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .highlight = "rule"sv,
                                   .args = {{
                                       .value = "custom_rule"sv,
                                       .address = "value34",
                                   }}}}});
        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule3",
                               .name = "rule3",
                               .tags = {{"type", "flow34"}, {"category", "category3"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .highlight = "rule"sv,
                                   .args = {{
                                       .value = "custom_rule"sv,
                                       .address = "value34",
                                   }}}}});

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context3, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule3",
                               .name = "custom_rule3",
                               .tags = {{"type", "flow34"}, {"category", "category3"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .highlight = "custom_rule"sv,
                                   .args = {{
                                       .value = "custom_rule"sv,
                                       .address = "value34",
                                   }}}}});

        ddwaf_object_free(&res);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);

    ddwaf_builder_destroy(builder);
}

} // namespace
