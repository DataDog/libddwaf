// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestEventSerializer, SerializeNothing)
{
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator);

    EXPECT_FALSE(serializer.has_events());

    ddwaf_result output;
    serializer.serialize(output);
    EXPECT_STREQ(output.data, nullptr);
}

TEST(TestEventSerializer, SerializeEmptyEvent)
{
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator);

    EXPECT_FALSE(serializer.has_events());
    serializer.insert({});
    EXPECT_TRUE(serializer.has_events());

    ddwaf_result output;
    serializer.serialize(output);
    EXPECT_STREQ(output.data, R"([{"rule":{"id":"","name":"","tags":{"type":"","category":""}},"rule_matches":[]}])");

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, SerializeSingleEventSingleMatch)
{
    ddwaf::event event;
    event.id = "xasd1022";
    event.name = "random rule";
    event.type = "test";
    event.category = "none";
    event.actions = {"block", "monitor"};
    event.matches = {
        {"value", "val", "random", "val", "query", {"root", "key"}}
    };

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator);

    EXPECT_FALSE(serializer.has_events());

    serializer.insert(std::move(event));

    EXPECT_TRUE(serializer.has_events());

    ddwaf_result output;
    serializer.serialize(output);

    EXPECT_THAT(output.actions, WithActions({"block", "monitor"}));
    EXPECT_THAT(output, WithEvent(
    {
        .id = "xasd1022",
        .name = "random rule",
        .type = "test",
        .category = "none",
        .actions = {"block", "monitor"},
        .matches = {{
            .op = "random",
            .op_value = "val",
            .address = "query",
            .path = {"root", "key"},
            .value = "value",
            .highlight = "val"
        }}
    }));
    EXPECT_STREQ(output.data, R"([{"rule":{"id":"xasd1022","name":"random rule","tags":{"type":"test","category":"none"},"on_match":["block","monitor"]},"rule_matches":[{"operator":"random","operator_value":"val","parameters":[{"address":"query","key_path":["root","key"],"value":"value","highlight":["val"]}]}]}])");

    ASSERT_NE(output.actions.array, nullptr);

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, SerializeSingleEventMultipleMatches)
{
    ddwaf::event event;
    event.id = "xasd1022";
    event.name = "random rule";
    event.type = "test";
    event.category = "none";
    event.actions = {"block", "monitor"};
    event.matches = {
        {"value", "val", "random", "val", "query", {"root", "key"}},
        {"string", "string", "match_regex", ".*", "response.body", {}},
        {"192.168.0.1", "192.168.0.1", "ip_match", "", "client.ip", {}},
        {"<script>", "", "is_xss", "", "path_params", {"key"}}
    };

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator);

    EXPECT_FALSE(serializer.has_events());

    serializer.insert(std::move(event));

    EXPECT_TRUE(serializer.has_events());

    ddwaf_result output;
    serializer.serialize(output);
    EXPECT_STREQ(output.data, R"([{"rule":{"id":"xasd1022","name":"random rule","tags":{"type":"test","category":"none"},"on_match":["block","monitor"]},"rule_matches":[{"operator":"random","operator_value":"val","parameters":[{"address":"query","key_path":["root","key"],"value":"value","highlight":["val"]}]},{"operator":"match_regex","operator_value":".*","parameters":[{"address":"response.body","key_path":[],"value":"string","highlight":["string"]}]},{"operator":"ip_match","operator_value":"","parameters":[{"address":"client.ip","key_path":[],"value":"192.168.0.1","highlight":["192.168.0.1"]}]},{"operator":"is_xss","operator_value":"","parameters":[{"address":"path_params","key_path":["key"],"value":"<script>","highlight":[]}]}]}])");

    ASSERT_NE(output.actions.array, nullptr);

    std::unordered_set<std::string_view> expected_actions{"block", "monitor"};
    std::unordered_set<std::string_view> found_actions;
    for (unsigned i = 0; i < output.actions.size; i++) {
        char *value = output.actions.array[i];
        EXPECT_NE(value, nullptr);
        found_actions.emplace(value);
    }

    EXPECT_EQ(expected_actions, found_actions);

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, SerializeMultipleEvents)
{
    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator);

    EXPECT_FALSE(serializer.has_events());

    {
        ddwaf::event event;
        event.id = "xasd1022";
        event.name = "random rule";
        event.type = "test";
        event.category = "none";
        event.actions = {"block", "monitor"};
        event.matches = {
            {"value", "val", "random", "val", "query", {"root", "key"}},
            {"string", "string", "match_regex", ".*", "response.body", {}},
            {"<script>", "", "is_xss", "", "path_params", {"key"}}
        };
        serializer.insert(std::move(event));
    }

    EXPECT_TRUE(serializer.has_events());

    {
        ddwaf::event event;
        event.id = "xasd1023";
        event.name = "pseudorandom rule";
        event.type = "test";
        event.category = "none";
        event.actions = {"unblock"};
        event.matches = {
            {"192.168.0.1", "192.168.0.1", "ip_match", "", "client.ip", {}}
        };
        serializer.insert(std::move(event));
    }

    EXPECT_TRUE(serializer.has_events());

    serializer.insert({});
    EXPECT_TRUE(serializer.has_events());

    ddwaf_result output;
    serializer.serialize(output);


    EXPECT_STREQ(output.data, R"([{"rule":{"id":"xasd1022","name":"random rule","tags":{"type":"test","category":"none"},"on_match":["block","monitor"]},"rule_matches":[{"operator":"random","operator_value":"val","parameters":[{"address":"query","key_path":["root","key"],"value":"value","highlight":["val"]}]},{"operator":"match_regex","operator_value":".*","parameters":[{"address":"response.body","key_path":[],"value":"string","highlight":["string"]}]},{"operator":"is_xss","operator_value":"","parameters":[{"address":"path_params","key_path":["key"],"value":"<script>","highlight":[]}]}]},{"rule":{"id":"xasd1023","name":"pseudorandom rule","tags":{"type":"test","category":"none"},"on_match":["unblock"]},"rule_matches":[{"operator":"ip_match","operator_value":"","parameters":[{"address":"client.ip","key_path":[],"value":"192.168.0.1","highlight":["192.168.0.1"]}]}]},{"rule":{"id":"","name":"","tags":{"type":"","category":""}},"rule_matches":[]}])");

    ASSERT_NE(output.actions.array, nullptr);

    std::unordered_set<std::string_view> expected_actions{"block", "monitor", "unblock"};
    std::unordered_set<std::string_view> found_actions;
    for (unsigned i = 0; i < output.actions.size; i++) {
        char *value = output.actions.array[i];
        EXPECT_NE(value, nullptr);
        found_actions.emplace(value);
    }

    EXPECT_EQ(expected_actions, found_actions);

    ddwaf_result_free(&output);
}

TEST(TestEventSerializer, SerializeEventNoActions)
{
    ddwaf::event event;
    event.id = "xasd1022";
    event.name = "random rule";
    event.type = "test";
    event.category = "none";
    event.matches = {
        {"value", "val", "random", "val", "query", {"root", "key"}}
    };

    ddwaf::obfuscator obfuscator;
    ddwaf::event_serializer serializer(obfuscator);

    EXPECT_FALSE(serializer.has_events());

    serializer.insert(std::move(event));

    EXPECT_TRUE(serializer.has_events());

    ddwaf_result output;
    serializer.serialize(output);
    EXPECT_STREQ(output.data, R"([{"rule":{"id":"xasd1022","name":"random rule","tags":{"type":"test","category":"none"}},"rule_matches":[{"operator":"random","operator_value":"val","parameters":[{"address":"query","key_path":["root","key"],"value":"value","highlight":["val"]}]}]}])");

    EXPECT_EQ(output.actions.array, nullptr);
    EXPECT_EQ(output.actions.size, 0);

    ddwaf_result_free(&output);
}


