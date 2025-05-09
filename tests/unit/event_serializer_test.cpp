// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

#include "builder/action_mapper_builder.hpp"
#include "event.hpp"
#include "rule.hpp"
#include "utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestEventSerializer, SerializeNothing)
{
    ddwaf::action_mapper actions;
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize({}, events_object, actions_object);

    EXPECT_EVENTS(output, ); // This means no events
    EXPECT_ACTIONS(output, {});
}

TEST(TestEventSerializer, SerializeEmptyEvent)
{
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, action_mapper_builder().build());

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize({ddwaf::event{}}, events_object, actions_object);

    EXPECT_EVENTS(output, {});
    EXPECT_ACTIONS(output, {});
}

TEST(TestEventSerializer, SerializeSingleEventSingleMatch)
{
    core_rule rule{"xasd1022", "random rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>(), {"block", "monitor_request"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {{.args = {{.name = "input",
                          .resolved = "value",
                          .address = "query",
                          .key_path = {"root", "key"}}},
        .highlights = {"val"},
        .operator_name = "random",
        .operator_value = "val"}};

    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    auto actions = builder.build();

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize({event}, events_object, actions_object);
    EXPECT_EVENTS(output, {.id = "xasd1022",
                              .name = "random rule",
                              .tags = {{"type", "test"}, {"category", "none"}},
                              .actions = {"block", "monitor_request"},
                              .matches = {{.op = "random",
                                  .op_value = "val",
                                  .highlight = "val",
                                  .args = {{.name = "input",
                                      .value = "value",
                                      .address = "query",
                                      .path = {"root", "key"}}}}}});

    EXPECT_ACTIONS(output,
        {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}},
            {"monitor_request", {}}});
}

TEST(TestEventSerializer, SerializeSingleEventMultipleMatches)
{
    core_rule rule{"xasd1022", "random rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>(), {"block", "monitor_request"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {{.args = {{.name = "input",
                          .resolved = "value",
                          .address = "query",
                          .key_path = {"root", "key"}}},
                         .highlights = {"val"},
                         .operator_name = "random",
                         .operator_value = "val"},
        {.args = {{.name = "input", .resolved = "string", .address = "response.body"}},
            .highlights = {"string"},
            .operator_name = "match_regex",
            .operator_value = ".*"},
        {.args = {{.name = "input", .resolved = "192.168.0.1", .address = "client.ip"}},
            .highlights = {"192.168.0.1"},
            .operator_name = "ip_match",
            .operator_value = ""},
        {.args = {{.name = "input",
             .resolved = "<script>",
             .address = "path_params",
             .key_path = {"key"}}},
            .highlights = {},
            .operator_name = "is_xss",
            .operator_value = ""}};

    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    auto actions = builder.build();

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize({event}, events_object, actions_object);

    EXPECT_EVENTS(output, {.id = "xasd1022",
                              .name = "random rule",
                              .tags = {{"type", "test"}, {"category", "none"}},
                              .actions = {"block", "monitor_request"},
                              .matches = {{.op = "random",
                                              .op_value = "val",
                                              .highlight = "val",
                                              .args = {{
                                                  .name = "input",
                                                  .value = "value",
                                                  .address = "query",
                                                  .path = {"root", "key"},
                                              }}},
                                  {
                                      .op = "match_regex",
                                      .op_value = ".*",
                                      .highlight = "string",
                                      .args = {{
                                          .name = "input",
                                          .value = "string",
                                          .address = "response.body",
                                      }},
                                  },
                                  {.op = "ip_match",
                                      .highlight = "192.168.0.1",
                                      .args = {{
                                          .name = "input",
                                          .value = "192.168.0.1",
                                          .address = "client.ip",
                                      }}},
                                  {.op = "is_xss",
                                      .args = {{
                                          .name = "input",
                                          .value = "<script>",
                                          .address = "path_params",
                                          .path = {"key"},
                                      }}}}});

    EXPECT_ACTIONS(output,
        {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}},
            {"monitor_request", {}}});
}

TEST(TestEventSerializer, SerializeMultipleEvents)
{
    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    builder.set_action("unblock", "unknown", {});
    auto actions = builder.build();

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    core_rule rule1{"xasd1022", "random rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>(), {"block", "monitor_request"}};
    core_rule rule2{"xasd1023", "pseudorandom rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>(), {"unblock"}};
    std::vector<ddwaf::event> events;
    {
        ddwaf::event event;
        event.rule = &rule1;
        event.matches = {{.args = {{.name = "input",
                              .resolved = "value",
                              .address = "query",
                              .key_path = {"root", "key"}}},
                             .highlights = {"val"},
                             .operator_name = "random",
                             .operator_value = "val"},
            {.args = {{.name = "input", .resolved = "string", .address = "response.body"}},
                .highlights = {"string"},
                .operator_name = "match_regex",
                .operator_value = ".*"},
            {.args = {{.name = "input",
                 .resolved = "<script>",
                 .address = "path_params",
                 .key_path = {"key"}}},
                .highlights = {},
                .operator_name = "is_xss",
                .operator_value = ""}};
        events.emplace_back(std::move(event));
    }

    {
        ddwaf::event event;
        event.rule = &rule2;
        event.matches = {
            {.args = {{.name = "input", .resolved = "192.168.0.1", .address = "client.ip"}},
                .highlights = {"192.168.0.1"},
                .operator_name = "ip_match",
                .operator_value = ""},
        };
        events.emplace_back(std::move(event));
    }

    events.emplace_back(ddwaf::event{});

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize(events, events_object, actions_object);
    EXPECT_EVENTS(output,
        {.id = "xasd1022",
            .name = "random rule",
            .tags = {{"type", "test"}, {"category", "none"}},
            .actions = {"block", "monitor_request"},
            .matches = {{.op = "random",
                            .op_value = "val",
                            .highlight = "val",
                            .args = {{
                                .value = "value",
                                .address = "query",
                                .path = {"root", "key"},
                            }}},
                {.op = "match_regex",
                    .op_value = ".*",
                    .highlight = "string",
                    .args = {{
                        .value = "string",
                        .address = "response.body",
                    }}},
                {.op = "is_xss",
                    .args = {{
                        .value = "<script>",
                        .address = "path_params",
                        .path = {"key"},
                    }}}}},
        {.id = "xasd1023",
            .name = "pseudorandom rule",
            .tags = {{"type", "test"}, {"category", "none"}},
            .actions = {"unblock"},
            .matches = {{.op = "ip_match",
                .highlight = "192.168.0.1",
                .args = {{
                    .value = "192.168.0.1",
                    .address = "client.ip",
                }}}}},
        {});

    EXPECT_ACTIONS(output,
        {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}},
            {"monitor_request", {}}, {"unknown", {}}});
}

TEST(TestEventSerializer, SerializeEventNoActions)
{
    core_rule rule{"xasd1022", "random rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>()};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {.args = {{.name = "input",
             .resolved = "value",
             .address = "query",
             .key_path = {"root", "key"}}},
            .highlights = {"val"},
            .operator_name = "random",
            .operator_value = "val"},
    };

    ddwaf::action_mapper actions;
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize({event}, events_object, actions_object);

    EXPECT_EVENTS(output, {.id = "xasd1022",
                              .name = "random rule",
                              .tags = {{"type", "test"}, {"category", "none"}},
                              .matches = {{.op = "random",
                                  .op_value = "val",
                                  .highlight = "val",
                                  .args = {{
                                      .value = "value",
                                      .address = "query",
                                      .path = {"root", "key"},
                                  }}}}});

    EXPECT_ACTIONS(output, {});
}

TEST(TestEventSerializer, SerializeAllTags)
{
    core_rule rule{"xasd1022", "random rule",
        {{"type", "test"}, {"category", "none"}, {"tag0", "value0"}, {"tag1", "value1"},
            {"confidence", "none"}},
        std::make_shared<expression>(), {"unblock"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {.args = {{.name = "input",
             .resolved = "value",
             .address = "query",
             .key_path = {"root", "key"}}},
            .highlights = {"val"},
            .operator_name = "random",
            .operator_value = "val"},
    };

    ddwaf::action_mapper_builder builder;
    builder.set_action("unblock", "unknown", {});
    auto actions = builder.build();

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize({event}, events_object, actions_object);

    EXPECT_EVENTS(output, {.id = "xasd1022",
                              .name = "random rule",
                              .tags = {{"type", "test"}, {"category", "none"}, {"tag0", "value0"},
                                  {"tag1", "value1"}, {"confidence", "none"}},
                              .actions = {"unblock"},
                              .matches = {{.op = "random",
                                  .op_value = "val",
                                  .highlight = "val",
                                  .args = {{
                                      .value = "value",
                                      .address = "query",
                                      .path = {"root", "key"},
                                  }}}}});

    EXPECT_ACTIONS(output, {{"unknown", {}}});
}

TEST(TestEventSerializer, NoMonitorActions)
{
    core_rule rule{"xasd1022", "random rule",
        {{"type", "test"}, {"category", "none"}, {"tag0", "value0"}, {"tag1", "value1"},
            {"confidence", "none"}},
        std::make_shared<expression>(), {"monitor"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {.args = {{.name = "input",
             .resolved = "value",
             .address = "query",
             .key_path = {"root", "key"}}},
            .highlights = {"val"},
            .operator_name = "random",
            .operator_value = "val"},
    };

    auto actions = action_mapper_builder().build();
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize({event}, events_object, actions_object);

    EXPECT_EVENTS(output, {.id = "xasd1022",
                              .name = "random rule",
                              .tags = {{"type", "test"}, {"category", "none"}, {"tag0", "value0"},
                                  {"tag1", "value1"}, {"confidence", "none"}},
                              .actions = {"monitor"},
                              .matches = {{.op = "random",
                                  .op_value = "val",
                                  .highlight = "val",
                                  .args = {{
                                      .value = "value",
                                      .address = "query",
                                      .path = {"root", "key"},
                                  }}}}});

    // Monitor action should not be reported here
    EXPECT_ACTIONS(output, {});
}

TEST(TestEventSerializer, UndefinedActions)
{
    core_rule rule{"xasd1022", "random rule",
        {{"type", "test"}, {"category", "none"}, {"tag0", "value0"}, {"tag1", "value1"},
            {"confidence", "none"}},
        std::make_shared<expression>(), {"unblock_request"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {.args = {{.name = "input",
             .resolved = "value",
             .address = "query",
             .key_path = {"root", "key"}}},
            .highlights = {"val"},
            .operator_name = "random",
            .operator_value = "val"},
    };

    auto actions = action_mapper_builder().build();
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize({event}, events_object, actions_object);

    EXPECT_EVENTS(output, {.id = "xasd1022",
                              .name = "random rule",
                              .tags = {{"type", "test"}, {"category", "none"}, {"tag0", "value0"},
                                  {"tag1", "value1"}, {"confidence", "none"}},
                              .actions = {"unblock_request"},
                              .matches = {{.op = "random",
                                  .op_value = "val",
                                  .highlight = "val",
                                  .args = {{
                                      .value = "value",
                                      .address = "query",
                                      .path = {"root", "key"},
                                  }}}}});

    // Monitor action should not be reported here
    EXPECT_ACTIONS(output, {});
}

TEST(TestEventSerializer, StackTraceAction)
{
    core_rule rule{"xasd1022", "random rule",
        {{"type", "test"}, {"category", "none"}, {"tag0", "value0"}, {"tag1", "value1"},
            {"confidence", "none"}},
        std::make_shared<expression>(), {"stack_trace"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {.args = {{.name = "input",
             .resolved = "value",
             .address = "query",
             .key_path = {"root", "key"}}},
            .highlights = {"val"},
            .operator_name = "random",
            .operator_value = "val"},
    };

    auto actions = action_mapper_builder().build();
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    auto output = owned_object::make_map();
    auto events_object = output.emplace("events", owned_object::make_array());
    auto actions_object = output.emplace("actions", owned_object::make_map());

    serializer.serialize({event}, events_object, actions_object);

    EXPECT_EVENTS(output, {.id = "xasd1022",
                              .name = "random rule",
                              .stack_id = "*",
                              .tags = {{"type", "test"}, {"category", "none"}, {"tag0", "value0"},
                                  {"tag1", "value1"}, {"confidence", "none"}},
                              .actions = {"stack_trace"},
                              .matches = {{.op = "random",
                                  .op_value = "val",
                                  .highlight = "val",
                                  .args = {{
                                      .value = "value",
                                      .address = "query",
                                      .path = {"root", "key"},
                                  }}}}});

    std::string stack_id;

    {
        auto data = ddwaf::test::object_to_json(events_object.ref());
        YAML::Node doc = YAML::Load(data.c_str());
        auto events = doc.as<std::list<ddwaf::test::event>>();
        ASSERT_EQ(events.size(), 1);
        stack_id = events.begin()->stack_id;
    }

    {
        auto data = ddwaf::test::object_to_json(actions_object.ref());
        YAML::Node doc = YAML::Load(data.c_str());
        auto obtained = doc.as<ddwaf::test::action_map>();
        EXPECT_TRUE(obtained.contains("generate_stack"));

        auto it = obtained.find("generate_stack");
        EXPECT_TRUE(it->second.contains("stack_id"));
        EXPECT_EQ(it->second.at("stack_id"), stack_id);
    }
}

} // namespace
