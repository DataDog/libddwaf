// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest/utils.hpp"

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

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize({}, output);
    EXPECT_EQ(ddwaf_object_type(&output.events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(&output.events), 0);
}

TEST(TestEventSerializer, SerializeEmptyEvent)
{
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, action_mapper_builder().build());

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize({ddwaf::event{}}, output);
    EXPECT_EVENTS(output, {});

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, SerializeSingleEventSingleMatch)
{
    ddwaf::rule rule{"xasd1022", "random rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>(), {"block", "monitor_request"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {{{{"input", "value", "query", {"root", "key"}}}, {"val"}, "random", "val"}};

    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    auto actions = builder.build();

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize({event}, output);
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

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, SerializeSingleEventMultipleMatches)
{
    ddwaf::rule rule{"xasd1022", "random rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>(), {"block", "monitor_request"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {{{{"input", "value", "query", {"root", "key"}}}, {"val"}, "random", "val"},
        {{{"input", "string", "response.body"}}, {"string"}, "match_regex", ".*"},
        {{{"input", "192.168.0.1", "client.ip"}}, {"192.168.0.1"}, "ip_match", ""},
        {{{"input", "<script>", "path_params", {"key"}}}, {}, "is_xss", ""}};

    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    auto actions = builder.build();

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize({event}, output);

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

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, SerializeMultipleEvents)
{
    ddwaf::action_mapper_builder builder;
    builder.set_action("monitor_request", "monitor_request", {});
    builder.set_action("unblock", "unknown", {});
    auto actions = builder.build();

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    ddwaf::rule rule1{"xasd1022", "random rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>(), {"block", "monitor_request"}};
    ddwaf::rule rule2{"xasd1023", "pseudorandom rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>(), {"unblock"}};
    std::vector<ddwaf::event> events;
    {
        ddwaf::event event;
        event.rule = &rule1;
        event.matches = {{{{"input", "value", "query", {"root", "key"}}}, {"val"}, "random", "val"},
            {{{"input", "string", "response.body"}}, {"string"}, "match_regex", ".*"},
            {{{"input", "<script>", "path_params", {"key"}}}, {}, "is_xss", ""}};
        events.emplace_back(std::move(event));
    }

    {
        ddwaf::event event;
        event.rule = &rule2;
        event.matches = {
            {{{"input", "192.168.0.1", "client.ip"}}, {"192.168.0.1"}, "ip_match", ""},
        };
        events.emplace_back(std::move(event));
    }

    events.emplace_back(ddwaf::event{});

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize(events, output);
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

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, SerializeEventNoActions)
{
    ddwaf::rule rule{"xasd1022", "random rule", {{"type", "test"}, {"category", "none"}},
        std::make_shared<expression>()};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {{{"input", "value", "query", {"root", "key"}}}, {"val"}, "random", "val"},
    };

    ddwaf::action_mapper actions;
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize({event}, output);

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

    EXPECT_EQ(output.actions.array, nullptr);
    EXPECT_EQ(ddwaf_object_size(&output.actions), 0);

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, SerializeAllTags)
{
    ddwaf::rule rule{"xasd1022", "random rule",
        {{"type", "test"}, {"category", "none"}, {"tag0", "value0"}, {"tag1", "value1"},
            {"confidence", "none"}},
        std::make_shared<expression>(), {"unblock"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {{{"input", "value", "query", {"root", "key"}}}, {"val"}, "random", "val"},
    };

    ddwaf::action_mapper_builder builder;
    builder.set_action("unblock", "unknown", {});
    auto actions = builder.build();

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize({event}, output);

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

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, NoMonitorActions)
{
    ddwaf::rule rule{"xasd1022", "random rule",
        {{"type", "test"}, {"category", "none"}, {"tag0", "value0"}, {"tag1", "value1"},
            {"confidence", "none"}},
        std::make_shared<expression>(), {"monitor"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {{{"input", "value", "query", {"root", "key"}}}, {"val"}, "random", "val"},
    };

    auto actions = action_mapper_builder().build();
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize({event}, output);

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

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, UndefinedActions)
{
    ddwaf::rule rule{"xasd1022", "random rule",
        {{"type", "test"}, {"category", "none"}, {"tag0", "value0"}, {"tag1", "value1"},
            {"confidence", "none"}},
        std::make_shared<expression>(), {"unblock_request"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {{{"input", "value", "query", {"root", "key"}}}, {"val"}, "random", "val"},
    };

    auto actions = action_mapper_builder().build();
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize({event}, output);

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

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, StackTraceAction)
{
    ddwaf::rule rule{"xasd1022", "random rule",
        {{"type", "test"}, {"category", "none"}, {"tag0", "value0"}, {"tag1", "value1"},
            {"confidence", "none"}},
        std::make_shared<expression>(), {"stack_trace"}};

    ddwaf::event event;
    event.rule = &rule;
    event.matches = {
        {{{"input", "value", "query", {"root", "key"}}}, {"val"}, "random", "val"},
    };

    auto actions = action_mapper_builder().build();
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator, actions);

    ddwaf_result output = DDWAF_RESULT_INITIALISER;
    serializer.serialize({event}, output);

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

    /*std::string stack_id;*/

    /*{*/
        /*auto data = ddwaf::test::object_to_json(output.events);*/
        /*YAML::Node doc = YAML::Load(data.c_str());*/
        /*auto events = doc.as<std::list<ddwaf::test::event>>();*/
        /*ASSERT_EQ(events.size(), 1);*/
        /*stack_id = events.begin()->stack_id;*/
    /*}*/

    /*{*/
        /*auto data = ddwaf::test::object_to_json(output.actions);*/
        /*YAML::Node doc = YAML::Load(data.c_str());*/
        /*auto obtained = doc.as<ddwaf::test::action_map>();*/
        /*EXPECT_TRUE(obtained.contains("generate_stack"));*/

        /*auto it = obtained.find("generate_stack");*/
        /*EXPECT_TRUE(it->second.contains("stack_id"));*/
        /*EXPECT_EQ(it->second.at("stack_id"), stack_id);*/
    /*}*/

    //ddwaf_result_free(&output);
}

} // namespace
