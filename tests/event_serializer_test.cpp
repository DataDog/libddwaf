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
    EXPECT_EVENT(output, {});

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

    EXPECT_EVENT(output,
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
    });

    EXPECT_THAT(output.actions, WithActions({"block", "monitor"}));

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

    EXPECT_EVENT(output,
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
        },
        {
            .op = "match_regex",
            .op_value = ".*",
            .address = "response.body",
            .value = "string",
            .highlight = "string"
        },
        {
            .op = "ip_match",
            .address = "client.ip",
            .value = "192.168.0.1",
            .highlight = "192.168.0.1"
        },
        {
            .op = "is_xss",
            .address = "path_params",
            .path = {"key"},
            .value = "<script>",
        }}
    });

    EXPECT_THAT(output.actions, WithActions({"block", "monitor"}));

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
    EXPECT_EVENT(output, {
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
        },
        {
            .op = "match_regex",
            .op_value = ".*",
            .address = "response.body",
            .value = "string",
            .highlight = "string"
        },
        {
            .op = "is_xss",
            .address = "path_params",
            .path = {"key"},
            .value = "<script>",
        }}
    },
    {
        .id = "xasd1023",
        .name = "pseudorandom rule",
        .type = "test",
        .category = "none",
        .actions = {"unblock"},
        .matches = {{
            .op = "ip_match",
            .address = "client.ip",
            .value = "192.168.0.1",
            .highlight = "192.168.0.1"
        }}
    },
    {}
    });

    EXPECT_THAT(output.actions, WithActions({"block", "monitor", "unblock"}));

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

    EXPECT_EVENT(output,
    {
        .id = "xasd1022",
        .name = "random rule",
        .type = "test",
        .category = "none",
        .matches = {{
            .op = "random",
            .op_value = "val",
            .address = "query",
            .path = {"root", "key"},
            .value = "value",
            .highlight = "val"
        }}
    });

    EXPECT_THAT(output.actions, WithActions({}));

    EXPECT_EQ(output.actions.array, nullptr);
    EXPECT_EQ(output.actions.size, 0);

    ddwaf_result_free(&output);
}


