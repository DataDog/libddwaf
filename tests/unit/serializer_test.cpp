// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

#include "builder/action_mapper_builder.hpp"
#include "rule.hpp"
#include "serializer.hpp"
#include "utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestEventSerializer, SerializeNothing)
{
    ddwaf::action_mapper actions;
    result_serializer serializer(nullptr, actions);

    std::vector<rule_result> results;
    auto store = object_store::make_context_store();
    attribute_collector collector;

    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();
    serializer.serialize(store, results, collector, deadline, output);

    EXPECT_EVENTS(result_object, ); // This means no results
    EXPECT_ACTIONS(result_object, {});
}

TEST(TestEventSerializer, SerializeEmptyEvent)
{
    result_serializer serializer(nullptr, action_mapper_builder().build());

    auto store = object_store::make_context_store();
    attribute_collector collector;
    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();

    std::unordered_map<std::string, std::string> tags{{"type", {}}, {"category", {}}};
    std::vector<std::string> actions;
    std::vector<rule_attribute> attributes;

    rule_result result{
        .event = rule_event{.rule{
                                .id = {},
                                .name = {},
                                .tags = tags,
                            },
            .matches = {}},
        .action_override = {},
        .actions = actions,
        .attributes = attributes,
    };

    std::vector<rule_result> results{result};
    serializer.serialize(store, results, collector, deadline, output);

    EXPECT_EVENTS(result_object, {});
    EXPECT_ACTIONS(result_object, {});
}

TEST(TestEventSerializer, SerializeSingleEventSingleMatch)
{
    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    auto action_definitions = builder.build();

    result_serializer serializer(nullptr, action_definitions);

    std::unordered_map<std::string, std::string> tags{{"type", "test"}, {"category", "none"}};
    std::vector<std::string> actions{"block", "monitor_request"};
    std::vector<rule_attribute> attributes;

    rule_result result{
        .event = rule_event{.rule{
                                .id = "xasd1022",
                                .name = "random rule",
                                .tags = tags,
                            },
            .matches = {{.args = {{.name = "input",
                             .resolved = "value"sv,
                             .address = "query",
                             .key_path = {"root", "key"}}},
                .highlights = {"val"sv},
                .operator_name = "random",
                .operator_value = "val"}}},
        .action_override = {},
        .actions = actions,
        .attributes = attributes,
    };

    std::vector<rule_result> results{result};
    auto store = object_store::make_context_store();
    attribute_collector collector;

    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();
    serializer.serialize(store, results, collector, deadline, output);
    EXPECT_EVENTS(result_object, {.id = "xasd1022",
                                     .name = "random rule",
                                     .block_id = "*",
                                     .tags = {{"type", "test"}, {"category", "none"}},
                                     .actions = {"block", "monitor_request"},
                                     .matches = {{.op = "random",
                                         .op_value = "val",
                                         .highlight = "val"sv,
                                         .args = {{.name = "input",
                                             .value = "value"sv,
                                             .address = "query",
                                             .path = {"root", "key"}}}}}});

    EXPECT_ACTIONS(
        result_object, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                              {"type", "auto"}, {"block_id", "*"}}},
                           {"monitor_request", {}}});
}

TEST(TestEventSerializer, SerializeSingleEventMultipleMatches)
{
    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    auto action_definitions = builder.build();

    result_serializer serializer(nullptr, action_definitions);

    std::unordered_map<std::string, std::string> tags{{"type", "test"}, {"category", "none"}};
    std::vector<std::string> actions{"block", "monitor_request"};
    std::vector<rule_attribute> attributes;

    rule_result result{
        .event =
            rule_event{
                .rule{
                    .id = "xasd1022",
                    .name = "random rule",
                    .tags = tags,
                },
                .matches = {{.args = {{.name = "input",
                                 .resolved = "value"sv,
                                 .address = "query",
                                 .key_path = {"root", "key"}}},
                                .highlights = {"val"sv},
                                .operator_name = "random",
                                .operator_value = "val"},
                    {.args =
                            {{.name = "input", .resolved = "string"sv, .address = "response.body"}},
                        .highlights = {"string"sv},
                        .operator_name = "match_regex",
                        .operator_value = ".*"},
                    {.args = {{.name = "input",
                         .resolved = "192.168.0.1"sv,
                         .address = "client.ip"}},
                        .highlights = {"192.168.0.1"sv},
                        .operator_name = "ip_match",
                        .operator_value = ""},
                    {.args = {{.name = "input",
                         .resolved = "<script>"sv,
                         .address = "path_params",
                         .key_path = {"key"}}},
                        .highlights = {},
                        .operator_name = "is_xss",
                        .operator_value = ""}},
            },
        .action_override = {},
        .actions = actions,
        .attributes = attributes,
    };

    std::vector<rule_result> results{result};
    auto store = object_store::make_context_store();
    attribute_collector collector;

    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();
    serializer.serialize(store, results, collector, deadline, output);

    EXPECT_EVENTS(result_object, {.id = "xasd1022",
                                     .name = "random rule",
                                     .block_id = "*",
                                     .tags = {{"type", "test"}, {"category", "none"}},
                                     .actions = {"block", "monitor_request"},
                                     .matches = {{.op = "random",
                                                     .op_value = "val",
                                                     .highlight = "val"sv,
                                                     .args = {{
                                                         .name = "input",
                                                         .value = "value"sv,
                                                         .address = "query",
                                                         .path = {"root", "key"},
                                                     }}},
                                         {
                                             .op = "match_regex",
                                             .op_value = ".*",
                                             .highlight = "string"sv,
                                             .args = {{
                                                 .name = "input",
                                                 .value = "string"sv,
                                                 .address = "response.body",
                                             }},
                                         },
                                         {.op = "ip_match",
                                             .highlight = "192.168.0.1"sv,
                                             .args = {{
                                                 .name = "input",
                                                 .value = "192.168.0.1"sv,
                                                 .address = "client.ip",
                                             }}},
                                         {.op = "is_xss",
                                             .args = {{
                                                 .name = "input",
                                                 .value = "<script>"sv,
                                                 .address = "path_params",
                                                 .path = {"key"},
                                             }}}}});

    EXPECT_ACTIONS(
        result_object, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                              {"type", "auto"}, {"block_id", "*"}}},
                           {"monitor_request", {}}});
}

TEST(TestEventSerializer, SerializeMultipleEvents)
{
    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    builder.set_action("unblock", "unknown", {});
    auto action_definitions = builder.build();

    result_serializer serializer(nullptr, action_definitions);

    std::vector<rule_attribute> attributes;

    std::unordered_map<std::string, std::string> tags0{{"type", "test"}, {"category", "none"}};
    std::vector<std::string> actions0{"block", "monitor_request"};

    rule_result result0{
        .event = rule_event{.rule{
                                .id = "xasd1022",
                                .name = "random rule",
                                .tags = tags0,
                            },
            .matches = {{.args = {{.name = "input",
                             .resolved = "value"sv,
                             .address = "query",
                             .key_path = {"root", "key"}}},
                            .highlights = {"val"sv},
                            .operator_name = "random",
                            .operator_value = "val"},
                {.args = {{.name = "input", .resolved = "string"sv, .address = "response.body"}},
                    .highlights = {"string"sv},
                    .operator_name = "match_regex",
                    .operator_value = ".*"},
                {.args = {{.name = "input",
                     .resolved = "<script>"sv,
                     .address = "path_params",
                     .key_path = {"key"}}},
                    .highlights = {},
                    .operator_name = "is_xss",
                    .operator_value = ""}}},
        .action_override = {},
        .actions = actions0,
        .attributes = attributes,
    };

    std::vector<std::string> actions1{"unblock"};

    rule_result result1{
        .event =
            rule_event{
                .rule{
                    .id = "xasd1023",
                    .name = "pseudorandom rule",
                    .tags = tags0,
                },
                .matches = {{.args = {{.name = "input",
                                 .resolved = "192.168.0.1"sv,
                                 .address = "client.ip"}},
                    .highlights = {"192.168.0.1"sv},
                    .operator_name = "ip_match",
                    .operator_value = ""}},
            },
        .action_override = {},
        .actions = actions1,
        .attributes = attributes,
    };

    std::unordered_map<std::string, std::string> tags2{{"type", {}}, {"category", {}}};
    std::vector<std::string> actions2{};
    rule_result result2{
        .event = rule_event{.rule{
                                .id = {},
                                .name = {},
                                .tags = tags2,
                            },
            .matches = {}},
        .action_override = {},
        .actions = actions2,
        .attributes = attributes,
    };

    std::vector<rule_result> results{result0, result1, result2};
    auto store = object_store::make_context_store();
    attribute_collector collector;

    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();
    serializer.serialize(store, results, collector, deadline, output);
    EXPECT_EVENTS(result_object,
        {.id = "xasd1022",
            .name = "random rule",
            .block_id = "*",
            .tags = {{"type", "test"}, {"category", "none"}},
            .actions = {"block", "monitor_request"},
            .matches = {{.op = "random",
                            .op_value = "val",
                            .highlight = "val"sv,
                            .args = {{
                                .value = "value"sv,
                                .address = "query",
                                .path = {"root", "key"},
                            }}},
                {.op = "match_regex",
                    .op_value = ".*",
                    .highlight = "string"sv,
                    .args = {{
                        .value = "string"sv,
                        .address = "response.body",
                    }}},
                {.op = "is_xss",
                    .args = {{
                        .value = "<script>"sv,
                        .address = "path_params",
                        .path = {"key"},
                    }}}}},
        {.id = "xasd1023",
            .name = "pseudorandom rule",
            .tags = {{"type", "test"}, {"category", "none"}},
            .actions = {"unblock"},
            .matches = {{.op = "ip_match",
                .highlight = "192.168.0.1"sv,
                .args = {{
                    .value = "192.168.0.1"sv,
                    .address = "client.ip",
                }}}}},
        {});

    EXPECT_ACTIONS(
        result_object, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                              {"type", "auto"}, {"block_id", "*"}}},
                           {"monitor_request", {}}, {"unknown", {}}});
}

TEST(TestEventSerializer, SerializeEventNoActions)
{
    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    auto action_definitions = builder.build();

    result_serializer serializer(nullptr, action_definitions);

    std::unordered_map<std::string, std::string> tags{{"type", "test"}, {"category", "none"}};
    std::vector<std::string> actions;
    std::vector<rule_attribute> attributes;

    rule_result result{
        .event =
            rule_event{
                .rule{
                    .id = "xasd1022",
                    .name = "random rule",
                    .tags = tags,
                },
                .matches = {{.args = {{.name = "input",
                                 .resolved = "value"sv,
                                 .address = "query",
                                 .key_path = {"root", "key"}}},
                    .highlights = {"val"sv},
                    .operator_name = "random",
                    .operator_value = "val"}},
            },
        .action_override = {},
        .actions = actions,
        .attributes = attributes,
    };

    std::vector<rule_result> results{result};
    auto store = object_store::make_context_store();
    attribute_collector collector;

    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();
    serializer.serialize(store, results, collector, deadline, output);
    EXPECT_EVENTS(result_object, {.id = "xasd1022",
                                     .name = "random rule",
                                     .tags = {{"type", "test"}, {"category", "none"}},
                                     .matches = {{.op = "random",
                                         .op_value = "val",
                                         .highlight = "val"sv,
                                         .args = {{
                                             .value = "value"sv,
                                             .address = "query",
                                             .path = {"root", "key"},
                                         }}}}});

    EXPECT_ACTIONS(result_object, {});
}

TEST(TestEventSerializer, SerializeAllTags)
{
    ddwaf::action_mapper_builder builder;
    builder.set_action("unblock", "unknown", {});
    auto action_definitions = builder.build();

    result_serializer serializer(nullptr, action_definitions);

    std::unordered_map<std::string, std::string> tags{{"type", "test"}, {"category", "none"},
        {"tag0", "value0"}, {"tag1", "value1"}, {"confidence", "none"}};
    std::vector<std::string> actions{"unblock"};
    std::vector<rule_attribute> attributes;

    rule_result result{
        .event =
            rule_event{
                .rule{
                    .id = "xasd1022",
                    .name = "random rule",
                    .tags = tags,
                },
                .matches = {{.args = {{.name = "input",
                                 .resolved = "value"sv,
                                 .address = "query",
                                 .key_path = {"root", "key"}}},
                    .highlights = {"val"sv},
                    .operator_name = "random",
                    .operator_value = "val"}},
            },
        .action_override = {},
        .actions = actions,
        .attributes = attributes,
    };

    std::vector<rule_result> results{result};
    auto store = object_store::make_context_store();
    attribute_collector collector;

    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();
    serializer.serialize(store, results, collector, deadline, output);
    EXPECT_EVENTS(
        result_object, {.id = "xasd1022",
                           .name = "random rule",
                           .tags = {{"type", "test"}, {"category", "none"}, {"tag0", "value0"},
                               {"tag1", "value1"}, {"confidence", "none"}},
                           .actions = {"unblock"},
                           .matches = {{.op = "random",
                               .op_value = "val",
                               .highlight = "val"sv,
                               .args = {{
                                   .value = "value"sv,
                                   .address = "query",
                                   .path = {"root", "key"},
                               }}}}});

    EXPECT_ACTIONS(result_object, {{"unknown", {}}});
}

TEST(TestEventSerializer, NoMonitorActions)
{
    auto action_definitions = action_mapper_builder().build();

    result_serializer serializer(nullptr, action_definitions);

    std::unordered_map<std::string, std::string> tags{{"type", "test"}, {"category", "none"},
        {"tag0", "value0"}, {"tag1", "value1"}, {"confidence", "none"}};
    std::vector<std::string> actions{"monitor"};
    std::vector<rule_attribute> attributes;

    rule_result result{
        .event =
            rule_event{
                .rule{
                    .id = "xasd1022",
                    .name = "random rule",
                    .tags = tags,
                },
                .matches = {{.args = {{.name = "input",
                                 .resolved = "value"sv,
                                 .address = "query",
                                 .key_path = {"root", "key"}}},
                    .highlights = {"val"sv},
                    .operator_name = "random",
                    .operator_value = "val"}},
            },
        .action_override = {},
        .actions = actions,
        .attributes = attributes,
    };

    std::vector<rule_result> results{result};
    auto store = object_store::make_context_store();
    attribute_collector collector;

    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();
    serializer.serialize(store, results, collector, deadline, output);
    EXPECT_EVENTS(
        result_object, {.id = "xasd1022",
                           .name = "random rule",
                           .tags = {{"type", "test"}, {"category", "none"}, {"tag0", "value0"},
                               {"tag1", "value1"}, {"confidence", "none"}},
                           .actions = {"monitor"},
                           .matches = {{.op = "random",
                               .op_value = "val",
                               .highlight = "val"sv,
                               .args = {{
                                   .value = "value"sv,
                                   .address = "query",
                                   .path = {"root", "key"},
                               }}}}});

    // Monitor action should not be reported here
    EXPECT_ACTIONS(result_object, {});
}

TEST(TestEventSerializer, UndefinedActions)
{
    auto action_definitions = action_mapper_builder().build();

    result_serializer serializer(nullptr, action_definitions);

    std::unordered_map<std::string, std::string> tags{{"type", "test"}, {"category", "none"},
        {"tag0", "value0"}, {"tag1", "value1"}, {"confidence", "none"}};
    std::vector<std::string> actions{"unblock_request"};
    std::vector<rule_attribute> attributes;

    rule_result result{
        .event =
            rule_event{
                .rule{
                    .id = "xasd1022",
                    .name = "random rule",
                    .tags = tags,
                },
                .matches = {{.args = {{.name = "input",
                                 .resolved = "value"sv,
                                 .address = "query",
                                 .key_path = {"root", "key"}}},
                    .highlights = {"val"sv},
                    .operator_name = "random",
                    .operator_value = "val"}},
            },
        .action_override = {},
        .actions = actions,
        .attributes = attributes,
    };

    std::vector<rule_result> results{result};
    auto store = object_store::make_context_store();
    attribute_collector collector;

    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();
    serializer.serialize(store, results, collector, deadline, output);
    EXPECT_EVENTS(
        result_object, {.id = "xasd1022",
                           .name = "random rule",
                           .tags = {{"type", "test"}, {"category", "none"}, {"tag0", "value0"},
                               {"tag1", "value1"}, {"confidence", "none"}},
                           .actions = {"unblock_request"},
                           .matches = {{.op = "random",
                               .op_value = "val",
                               .highlight = "val"sv,
                               .args = {{
                                   .value = "value"sv,
                                   .address = "query",
                                   .path = {"root", "key"},
                               }}}}});

    // Monitor action should not be reported here
    EXPECT_ACTIONS(result_object, {});
}

TEST(TestEventSerializer, StackTraceAction)
{
    auto action_definitions = action_mapper_builder().build();

    result_serializer serializer(nullptr, action_definitions);

    std::unordered_map<std::string, std::string> tags{{"type", "test"}, {"category", "none"},
        {"tag0", "value0"}, {"tag1", "value1"}, {"confidence", "none"}};
    std::vector<std::string> actions{"stack_trace"};
    std::vector<rule_attribute> attributes;

    rule_result result{
        .event =
            rule_event{
                .rule{
                    .id = "xasd1022",
                    .name = "random rule",
                    .tags = tags,
                },
                .matches = {{.args = {{.name = "input",
                                 .resolved = "value"sv,
                                 .address = "query",
                                 .key_path = {"root", "key"}}},
                    .highlights = {"val"sv},
                    .operator_name = "random",
                    .operator_value = "val"}},
            },
        .action_override = {},
        .actions = actions,
        .attributes = attributes,
    };

    std::vector<rule_result> results{result};
    auto store = object_store::make_context_store();
    attribute_collector collector;

    ddwaf::timer deadline{2s};
    auto [result_object, output] = serializer.initialise_result_object();
    serializer.serialize(store, results, collector, deadline, output);
    EXPECT_EVENTS(
        result_object, {.id = "xasd1022",
                           .name = "random rule",
                           .stack_id = "*",
                           .tags = {{"type", "test"}, {"category", "none"}, {"tag0", "value0"},
                               {"tag1", "value1"}, {"confidence", "none"}},
                           .actions = {"stack_trace"},
                           .matches = {{.op = "random",
                               .op_value = "val",
                               .highlight = "val"sv,
                               .args = {{
                                   .value = "value"sv,
                                   .address = "query",
                                   .path = {"root", "key"},
                               }}}}});

    std::string stack_id;

    {
        auto data = ddwaf::test::object_to_json(output.events.ref());
        YAML::Node doc = YAML::Load(data.c_str());
        auto results = doc.as<std::list<ddwaf::test::event>>();
        ASSERT_EQ(results.size(), 1);
        stack_id = results.begin()->stack_id;
    }

    {
        auto data = ddwaf::test::object_to_json(output.actions.ref());
        YAML::Node doc = YAML::Load(data.c_str());
        auto obtained = doc.as<ddwaf::test::action_map>();
        EXPECT_TRUE(obtained.contains("generate_stack"));

        auto it = obtained.find("generate_stack");
        EXPECT_TRUE(it->second.contains("stack_id"));
        EXPECT_EQ(std::get<std::string>(it->second.at("stack_id")), stack_id);
    }
}

} // namespace
