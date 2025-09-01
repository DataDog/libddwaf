// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/processors/uri_parse";

TEST(TestUriParseIntegration, Preprocessor)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 2);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.io.net.url"));
    EXPECT_TRUE(address_set.contains("server.io.net.request.url"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object *url = ddwaf_object_insert_key(&map, STRL("server.io.net.url"), alloc);
    ddwaf_object_set_string(
        url, STRL("http://datadoghq.com:8080/path?query=value#something"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "^datadoghq.com$",
                               .highlight = "datadoghq.com"sv,
                               .args = {{
                                   .value = "datadoghq.com"sv,
                                   .address = "server.io.net.request.url",
                                   .path = {"host"},
                               }}}}});

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestUriParseIntegration, Postprocessor)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 1);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.io.net.url"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object *url = ddwaf_object_insert_key(&map, STRL("server.io.net.url"), alloc);
    ddwaf_object_set_string(
        url, STRL("http://datadoghq.com:8080/path?query=value#something"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    EXPECT_JSON(*attributes,
        R"({"server.io.net.request.url":{"scheme":"http","userinfo":"","host":"datadoghq.com","port":8080,"path":"/path","query":{"query":"value"},"fragment":"something"}})");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestUriParseIntegration, Processor)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 2);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.io.net.url"));
    EXPECT_TRUE(address_set.contains("server.io.net.request.url"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object *url = ddwaf_object_insert_key(&map, STRL("server.io.net.url"), alloc);
    ddwaf_object_set_string(
        url, STRL("http://datadoghq.com:8080/path?query=value#something"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "^datadoghq.com$",
                               .highlight = "datadoghq.com"sv,
                               .args = {{
                                   .value = "datadoghq.com"sv,
                                   .address = "server.io.net.request.url",
                                   .path = {"host"},
                               }}}}});

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    EXPECT_JSON(*attributes,
        R"({"server.io.net.request.url":{"scheme":"http","userinfo":"","host":"datadoghq.com","port":8080,"path":"/path","query":{"query":"value"},"fragment":"something"}})");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
