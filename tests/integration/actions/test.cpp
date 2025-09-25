// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <regex>

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

using namespace ddwaf;
using namespace std::literals;

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

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block"sv,
                                   .args = {{
                                       .value = "block"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(
            res, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                        {"type", "auto"}, {"block_id", "*"}}}});
        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "stack_trace"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "stack-trace-rule",
                               .name = "stack-trace-rule",
                               .stack_id = "*",
                               .tags = {{"type", "flow2"}, {"category", "category2"}},
                               .actions = {"stack_trace"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "stack_trace",
                                   .highlight = "stack_trace"sv,
                                   .args = {{
                                       .value = "stack_trace"sv,
                                       .address = "value",
                                   }}}}});

        std::string stack_id;
        {
            const auto *object = ddwaf_object_find(&res, STRL("events"));
            ASSERT_NE(object, nullptr);
            auto data = ddwaf::test::object_to_json(*object);
            YAML::Node doc = YAML::Load(data.c_str());
            auto events = doc.as<std::list<ddwaf::test::event>>();
            ASSERT_EQ(events.size(), 1);
            stack_id = events.begin()->stack_id;
        }

        {
            const auto *object = ddwaf_object_find(&res, STRL("actions"));
            ASSERT_NE(object, nullptr);

            auto data = ddwaf::test::object_to_json(*object);
            YAML::Node doc = YAML::Load(data.c_str());
            auto obtained = doc.as<ddwaf::test::action_map>();
            EXPECT_TRUE(obtained.contains("generate_stack"));

            auto it = obtained.find("generate_stack");
            EXPECT_EQ(it->second.size(), 1);
            EXPECT_TRUE(it->second.contains("stack_id"));
            EXPECT_EQ(std::get<std::string>(it->second.at("stack_id")), stack_id);
        }

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "extract_schema"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "extract-schema-rule",
                               .name = "extract-schema-rule",
                               .tags = {{"type", "flow3"}, {"category", "category3"}},
                               .actions = {"extract_schema"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "extract_schema",
                                   .highlight = "extract_schema"sv,
                                   .args = {{
                                       .value = "extract_schema"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {{"generate_schema", {}}});

        ddwaf_object_free(&res);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "unblock"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "unblock-rule",
                               .name = "unblock-rule",
                               .tags = {{"type", "flow4"}, {"category", "category4"}},
                               .actions = {"unblock"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "unblock",
                                   .highlight = "unblock"sv,
                                   .args = {{
                                       .value = "unblock"sv,
                                       .address = "value",
                                   }}}}});

        // The unblock action doesn't exist, so no user action is reported, however
        // the rule definition within the event still contains the unblock action
        EXPECT_ACTIONS(res, {});
        ddwaf_object_free(&res);
    }
    ddwaf_context_destroy(context1);
    ddwaf_destroy(handle);
}

TEST(TestActionsIntegration, OverrideDefaultAction)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("default_actions.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block"sv,
                                   .args = {{
                                       .value = "block"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(
            res, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                        {"type", "auto"}, {"block_id", "*"}}}});
        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto actions = yaml_to_object(
            R"({actions: [{id: block, type: redirect_request, parameters: {location: http://google.com, status_code: 303}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("actions"), &actions, nullptr);
        ddwaf_object_free(&actions);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block"sv,
                                   .args = {{
                                       .value = "block"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res,
            {{"redirect_request",
                {{"location", "http://google.com"}, {"status_code", 303ULL}, {"block_id", "*"}}}});
        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestActionsIntegration, AddNewAction)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("default_actions.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "unblock"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "unblock-rule",
                               .name = "unblock-rule",
                               .tags = {{"type", "flow4"}, {"category", "category4"}},
                               .actions = {"unblock"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "unblock",
                                   .highlight = "unblock"sv,
                                   .args = {{
                                       .value = "unblock"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {});
        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto actions = yaml_to_object(
            R"({actions: [{id: unblock, type: unblock_request, parameters: {code: 303}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("actions"), &actions, nullptr);
        ddwaf_object_free(&actions);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "unblock"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "unblock-rule",
                               .name = "unblock-rule",
                               .tags = {{"type", "flow4"}, {"category", "category4"}},
                               .actions = {"unblock"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "unblock",
                                   .highlight = "unblock"sv,
                                   .args = {{
                                       .value = "unblock"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {{"unblock_request", {{"code", 303ULL}}}});

        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestActionsIntegration, EmptyOrInvalidActions)
{
    auto rule = read_file("invalid_actions.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object res;
    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

    EXPECT_EVENTS(res, {.id = "block-rule",
                           .name = "block-rule",
                           .block_id = "*",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .actions = {"block"},
                           .matches = {{.op = "match_regex",
                               .op_value = "^block",
                               .highlight = "block"sv,
                               .args = {{
                                   .value = "block"sv,
                                   .address = "value",
                               }}}}});

    EXPECT_ACTIONS(res, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                               {"type", "auto"}, {"block_id", "*"}}}});
    ddwaf_object_free(&res);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestActionsIntegration, ActionTypes)
{
    auto rule = read_file("action_types.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    ddwaf_object tmp;
    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "sanitize"));

    ddwaf_object res;
    EXPECT_EQ(ddwaf_run(context1, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

    EXPECT_EVENTS(res, {.id = "sanitize-rule",
                           .name = "sanitize-rule",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .actions = {"sanitize"},
                           .matches = {{.op = "match_regex",
                               .op_value = "^sanitize",
                               .highlight = "sanitize"sv,
                               .args = {{
                                   .value = "sanitize"sv,
                                   .address = "value",
                               }}}}});

    EXPECT_ACTIONS(res, {{"sanitize_something", {{"string", "thisisastring"}, {"int64", -200},
                                                    {"uint64", 18446744073709551615ULL},
                                                    {"double", 22.22}, {"bool", true}}}});
    ddwaf_object_free(&res);

    ddwaf_context_destroy(context1);
    ddwaf_destroy(handle);
}

TEST(TestActionsIntegration, PreventBlockIDInjectionOnBlock)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("default_actions.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block"sv,
                                   .args = {{
                                       .value = "block"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(
            res, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                        {"type", "auto"}, {"block_id", "*"}}}});
        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto actions = yaml_to_object(
            R"({actions: [{id: block, type: block_request, parameters: {status_code: 404, "block_id": "this is an injected ID", "display_id": true}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("actions"), &actions, nullptr);
        ddwaf_object_free(&actions);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block"sv,
                                   .args = {{
                                       .value = "block"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res,
            {{"block_request", {{"status_code", 404ULL}, {"grpc_status_code", 10ULL},
                                   {"type", "auto"}, {"block_id", "*"}, {"display_id", true}}}});

        const auto *actions = ddwaf_object_find(&res, STRL("actions"));
        ASSERT_NE(actions, nullptr);

        const auto *block_params = ddwaf_object_find(actions, STRL("block_request"));
        ASSERT_NE(block_params, nullptr);

        const auto *block_id = ddwaf_object_find(block_params, STRL("block_id"));
        ASSERT_NE(block_id, nullptr);

        std::regex uuid_regex{"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-1b[a-f0-9]{2}-[a-f0-9]{12}$",
            std::regex_constants::icase};
        std::string block_id_str{
            ddwaf_object_get_string(block_id, nullptr), ddwaf_object_length(block_id)};

        EXPECT_TRUE(std::regex_match(block_id_str, uuid_regex)) << block_id_str;

        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestActionsIntegration, PreventBlockIDInjectionOnRedirect)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("default_actions.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object tmp;
    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block"sv,
                                   .args = {{
                                       .value = "block"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(
            res, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                        {"type", "auto"}, {"block_id", "*"}}}});
        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto actions = yaml_to_object(
            R"({actions: [{id: block, type: redirect_request, parameters: {status_code: 303, "location": "http://google.com", "block_id": "this is an injected ID", "display_id": true}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("actions"), &actions, nullptr);
        ddwaf_object_free(&actions);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "block"));

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "block-rule",
                               .name = "block-rule",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^block",
                                   .highlight = "block"sv,
                                   .args = {{
                                       .value = "block"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(
            res, {{"redirect_request", {{"location", "http://google.com"}, {"status_code", 303ULL},
                                           {"block_id", "*"}, {"display_id", true}}}});

        const auto *actions = ddwaf_object_find(&res, STRL("actions"));
        ASSERT_NE(actions, nullptr);

        const auto *block_params = ddwaf_object_find(actions, STRL("redirect_request"));
        ASSERT_NE(block_params, nullptr);

        const auto *block_id = ddwaf_object_find(block_params, STRL("block_id"));
        ASSERT_NE(block_id, nullptr);

        std::regex uuid_regex{"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-1b[a-f0-9]{2}-[a-f0-9]{12}$",
            std::regex_constants::icase};
        std::string block_id_str{
            ddwaf_object_get_string(block_id, nullptr), ddwaf_object_length(block_id)};

        EXPECT_TRUE(std::regex_match(block_id_str, uuid_regex)) << block_id_str;

        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestActionsIntegration, PreventStackIDInjection)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("default_actions.yaml", base_dir);
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object tmp;
    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "stack_trace"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "stack-trace-rule",
                               .name = "stack-trace-rule",
                               .stack_id = "*",
                               .tags = {{"type", "flow2"}, {"category", "category2"}},
                               .actions = {"stack_trace"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "stack_trace",
                                   .highlight = "stack_trace"sv,
                                   .args = {{
                                       .value = "stack_trace"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {{"generate_stack", {{"stack_id", "*"}}}});
        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto actions = yaml_to_object(
            R"({actions: [{id: stack_trace, type: generate_stack, parameters: {"stack_id": "this is an injected ID"}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("actions"), &actions, nullptr);
        ddwaf_object_free(&actions);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "stack_trace"));

        ddwaf_object res;
        EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &res, LONG_TIME), DDWAF_MATCH);

        EXPECT_EVENTS(res, {.id = "stack-trace-rule",
                               .name = "stack-trace-rule",
                               .stack_id = "*",
                               .tags = {{"type", "flow2"}, {"category", "category2"}},
                               .actions = {"stack_trace"},
                               .matches = {{.op = "match_regex",
                                   .op_value = "stack_trace",
                                   .highlight = "stack_trace"sv,
                                   .args = {{
                                       .value = "stack_trace"sv,
                                       .address = "value",
                                   }}}}});

        EXPECT_ACTIONS(res, {{"generate_stack", {{"stack_id", "*"}}}});

        const auto *actions = ddwaf_object_find(&res, STRL("actions"));
        ASSERT_NE(actions, nullptr);

        const auto *stack_params = ddwaf_object_find(actions, STRL("generate_stack"));
        ASSERT_NE(stack_params, nullptr);

        const auto *stack_id = ddwaf_object_find(stack_params, STRL("stack_id"));
        ASSERT_NE(stack_id, nullptr);

        std::regex uuid_regex{"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-1b[a-f0-9]{2}-[a-f0-9]{12}$",
            std::regex_constants::icase};
        std::string stack_id_str{
            ddwaf_object_get_string(stack_id, nullptr), ddwaf_object_length(stack_id)};

        EXPECT_TRUE(std::regex_match(stack_id_str, uuid_regex)) << stack_id_str;

        ddwaf_object_free(&res);

        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

} // namespace
