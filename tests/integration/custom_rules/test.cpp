// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../test.h"
#include "ddwaf.h"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/custom_rules/";
} // namespace

// Custom rules can be used instead of base rules
TEST(TestCustomRules, InitWithoutBaseRules)
{
    auto rule = readFile("custom_rules.yaml", base_dir);
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
    auto rule = readFile("custom_rules_and_rules.yaml", base_dir);
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

// Regular custom rules have precedence over regular base rules
TEST(TestCustomRules, RegularCustomRulesPrecedence)
{
    auto rule = readFile("custom_rules_and_rules.yaml", base_dir);
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
        ddwaf_object_map_add(&parameter, "value3", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule3",
                               .name = "custom_rule3",
                               .tags = {{"type", "flow34"}, {"category", "category3"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value3",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
}

// Priority custom rules have precedence over priority base rules
TEST(TestCustomRules, PriorityCustomRulesPrecedence)
{
    auto rule = readFile("custom_rules_and_rules.yaml", base_dir);
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
        ddwaf_object_map_add(&parameter, "value4", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value4",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
}

// Global rules precedence test Priority Custom > Priority Base > Custom > Base
TEST(TestCustomRules, CustomRulesPrecedence)
{
    auto rule = readFile("custom_rules_and_rules.yaml", base_dir);
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
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
}

// Custom rules can be updated when base rules exist
TEST(TestCustomRules, UpdateFromBaseRules)
{
    auto rule = readFile("custom_rules_base_rules_only.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto update = readFile("custom_rules.yaml", base_dir);
    ASSERT_TRUE(update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_update(handle1, &update, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&update);

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

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
}

// Custom rules can be updated when custom rules already exist
TEST(TestCustomRules, UpdateFromCustomRules)
{
    auto rule = readFile("custom_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto update = readRule(
        R"({custom_rules: [{id: custom_rule5, name: custom_rule5, tags: {type: flow5, category: category5}, conditions: [{operator: match_regex, parameters: {inputs: [{address: value34}], regex: custom_rule}}]}]})");

    ASSERT_TRUE(update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_update(handle1, &update, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&update);

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

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule5",
                               .name = "custom_rule5",
                               .tags = {{"type", "flow5"}, {"category", "category5"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
}

// Remove all custom rules when no other rules are available
TEST(TestCustomRules, UpdateWithEmptyRules)
{
    auto rule = readFile("custom_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto update = readRule(R"({custom_rules: []})");
    ASSERT_TRUE(update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_update(handle1, &update, nullptr);
    ASSERT_EQ(handle2, nullptr);
    ddwaf_object_free(&update);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle1);
}

// Remove all custom rules when base rules are available
TEST(TestCustomRules, UpdateRemoveAllCustomRules)
{
    auto rule = readFile("custom_rules_and_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto update = readRule(R"({custom_rules: []})");
    ASSERT_TRUE(update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_update(handle1, &update, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&update);

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

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
}

// Ensure that existing custom rules are unaffected by overrides
TEST(TestCustomRules, CustomRulesUnaffectedByOverrides)
{
    auto rule = readFile("custom_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto update = readRule(
        R"({rules_override: [{rules_target: [{tags: {category: category4}}], enabled: false}]})");
    ASSERT_TRUE(update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_update(handle1, &update, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&update);

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

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
}

// Ensure that custom rules are unaffected by overrides after an update
TEST(TestCustomRules, CustomRulesUnaffectedByOverridesAfterUpdate)
{
    auto rule = readFile("custom_rules_base_rules_only.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto update = readRule(
        R"({rules_override: [{rules_target: [{tags: {category: category4}}], enabled: false}]})");
    ASSERT_TRUE(update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_update(handle1, &update, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&update);

    auto rules_update = readFile("custom_rules.yaml", base_dir);
    ASSERT_TRUE(rules_update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle3 = ddwaf_update(handle2, &rules_update, nullptr);
    ASSERT_NE(handle3, nullptr);
    ddwaf_object_free(&rules_update);

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

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .address = "value4",
                                   .value = "custom_rule",
                                   .highlight = "rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value4", ddwaf_object_string(&tmp, "custom_rule"));

        EXPECT_EQ(ddwaf_run(context2, &parameter, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value4", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context3, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value4",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);
}

// Ensure that existing custom rules are unaffected by overrides
TEST(TestCustomRules, CustomRulesAffectedByExclusions)
{
    auto rule = readFile("custom_rules_and_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto update = readRule(
        R"({exclusions: [{id: custom_rule4_exclude, rules_target: [{rule_id: custom_rule4}]}]})");
    ASSERT_TRUE(update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_update(handle1, &update, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&update);

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

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule4",
                               .name = "custom_rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
}

// Ensure that custom rules are affected by overrides after an update
TEST(TestCustomRules, CustomRulesAffectedByExclusionsAfterUpdate)
{
    auto rule = readFile("custom_rules_base_rules_only.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle1 = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    auto update = readRule(
        R"({exclusions: [{id: custom_rule4_exclude, rules_target: [{tags: {category: category4}}]}]})");
    ASSERT_TRUE(update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_update(handle1, &update, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&update);

    auto rules_update = readFile("custom_rules.yaml", base_dir);
    ASSERT_TRUE(rules_update.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle3 = ddwaf_update(handle2, &rules_update, nullptr);
    ASSERT_NE(handle3, nullptr);
    ddwaf_object_free(&rules_update);

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

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule4",
                               .name = "rule4",
                               .tags = {{"type", "flow34"}, {"category", "category4"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "rule"}}});
        EXPECT_THAT(res.actions, WithActions({"block"}));

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context2, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "rule3",
                               .name = "rule3",
                               .tags = {{"type", "flow34"}, {"category", "category3"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "rule"}}});

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value34", ddwaf_object_string(&tmp, "custom_rule"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context3, &parameter, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "custom_rule3",
                               .name = "custom_rule3",
                               .tags = {{"type", "flow34"}, {"category", "category3"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "custom_rule",
                                   .address = "value34",
                                   .value = "custom_rule",
                                   .highlight = "custom_rule"}}});

        ddwaf_result_free(&res);
        ddwaf_object_free(&parameter);
    }

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);
    ddwaf_context_destroy(context3);
}
