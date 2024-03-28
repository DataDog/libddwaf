// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../test_utils.hpp"
#include "ddwaf.h"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/actions/";

TEST(TestActionsIntegration, DefaultActions)
{
    auto rule = read_file("default_actions.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block",
                                   .args = {{
                                       .value = "block",
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});
        ddwaf_result_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "stack_trace"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "stack-trace-rule",
                               .name = "stack-trace-rule",
                               .stack_id = "*",
                               .tags = {{"type", "flow2"}, {"category", "category2"}},
                               .actions = {"stack_trace"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "stack_trace",
                                   .highlight = "stack_trace",
                                   .args = {{
                                       .value = "stack_trace",
                                       .address = "value",
                                   }}}}});

        std::string stack_id;
        {
            auto data = ddwaf::test::object_to_json(res.events);
            YAML::Node doc = YAML::Load(data.c_str());
            auto events = doc.as<std::list<ddwaf::test::event>>();
            ASSERT_EQ(events.size(), 1);
            stack_id = events.begin()->stack_id;
        }

        {
            auto data = ddwaf::test::object_to_json(res.actions);
            YAML::Node doc = YAML::Load(data.c_str());
            auto obtained = doc.as<ddwaf::test::action_map>();
            EXPECT_TRUE(obtained.contains("generate_stack"));

            auto it = obtained.find("generate_stack");
            EXPECT_EQ(it->second.size(), 1);
            EXPECT_TRUE(it->second.contains("stack_id"));
            EXPECT_EQ(it->second.at("stack_id"), stack_id);
        }

        ddwaf_result_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "extract_schema"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "extract-schema-rule",
                               .name = "extract-schema-rule",
                               .tags = {{"type", "flow3"}, {"category", "category3"}},
                               .actions = {"extract_schema"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "extract_schema",
                                   .highlight = "extract_schema",
                                   .args = {{
                                       .value = "extract_schema",
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {{"generate_schema", {}}});

        ddwaf_result_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "unblock"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "unblock-rule",
                               .name = "unblock-rule",
                               .tags = {{"type", "flow4"}, {"category", "category4"}},
                               .actions = {"unblock"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "unblock",
                                   .highlight = "unblock",
                                   .args = {{
                                       .value = "unblock",
                                       .address = "value",
                                   }}}}});

        // The unblock action doesn't exist, so no user action is reported, however
        // the rule definition within the event still contains the unblock action
        EXPECT_ACTIONS(res, {});
        ddwaf_result_free(&res);
    }
    ddwaf_context_destroy(context1);
    ddwaf_destroy(handle);
}

TEST(TestActionsIntegration, OverrideDefaultAction)
{
    auto rule = read_file("default_actions.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block",
                                   .args = {{
                                       .value = "block",
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}});
        ddwaf_result_free(&res);

        ddwaf_context_destroy(context);
    }

    {
        auto overrides = yaml_to_object(
            R"({actions: [{id: block, type: redirect_request, parameters: {location: http://google.com, status_code: 303}}]})");
        auto *new_handle = ddwaf_update(handle, &overrides, nullptr);
        ddwaf_object_free(&overrides);
        ASSERT_NE(new_handle, nullptr);

        ddwaf_destroy(handle);
        handle = new_handle;
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block",
                                   .args = {{
                                       .value = "block",
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res,
            {{"redirect_request", {{"location", "http://google.com"}, {"status_code", "303"}}}});
        ddwaf_result_free(&res);

        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestActionsIntegration, AddNewAction)
{
    auto rule = read_file("default_actions.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "unblock"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "unblock-rule",
                               .name = "unblock-rule",
                               .tags = {{"type", "flow4"}, {"category", "category4"}},
                               .actions = {"unblock"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "unblock",
                                   .highlight = "unblock",
                                   .args = {{
                                       .value = "unblock",
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {});
        ddwaf_result_free(&res);

        ddwaf_context_destroy(context);
    }

    {
        auto overrides = yaml_to_object(
            R"({actions: [{id: unblock, type: unblock_request, parameters: {code: 303}}]})");
        auto *new_handle = ddwaf_update(handle, &overrides, nullptr);
        ddwaf_object_free(&overrides);
        ASSERT_NE(new_handle, nullptr);

        ddwaf_destroy(handle);
        handle = new_handle;
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "unblock"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "unblock-rule",
                               .name = "unblock-rule",
                               .tags = {{"type", "flow4"}, {"category", "category4"}},
                               .actions = {"unblock"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "unblock",
                                   .highlight = "unblock",
                                   .args = {{
                                       .value = "unblock",
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {{"unblock_request", {{"code", "303"}}}});

        ddwaf_result_free(&res);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

} // namespace
