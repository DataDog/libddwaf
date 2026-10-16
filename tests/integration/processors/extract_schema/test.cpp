// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/processors/extract_schema";

TEST(TestExtractSchemaIntegration, Postprocessor)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 2);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc), STRL("value"), alloc);

    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    auto schema = test::object_to_json(*attributes);
    EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, Preprocessor)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 3);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.body.schema"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc), STRL("value"), alloc);
    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "equals",
                               .op_value = "",
                               .highlight = ""sv,
                               .args = {{
                                   .value = "8"sv,
                                   .address = "server.request.body.schema",
                                   .path = {0},
                               }}}}});

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, Processor)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 4);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.body.schema"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc), STRL("value"), alloc);

    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "equals",
                               .op_value = "",
                               .highlight = ""sv,
                               .args = {{
                                   .value = "8"sv,
                                   .address = "server.request.body.schema",
                                   .path = {0},
                               }}}}});

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    auto schema = test::object_to_json(*attributes);
    EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ProcessorWithScannerByTags)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    auto scanner = read_json_file("scanners.json", base_dir);
    ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
    ddwaf_object_destroy(&scanner, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 2, alloc);

    auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_map(values, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(values, STRL("email"), alloc), STRL("data@datadoghq.com"), alloc);

    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object out;
    ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);
    EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0),
        R"([{"email":[8,{"category":"pii","type":"email"}]}])");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);

    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, ProcessorWithScannerByID)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    auto rule = read_json_file("processor_with_scanner_by_id.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    auto scanner = read_json_file("scanners.json", base_dir);
    ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
    ddwaf_object_destroy(&scanner, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 2, alloc);

    auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_map(values, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(values, STRL("email"), alloc), STRL("data@datadoghq.com"), alloc);

    auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object out;
    ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);
    EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0),
        R"([{"email":[8,{"category":"pii","type":"email"}]}])");

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, ProcessorUpdate)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_destroy(&scanner, alloc);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(values, STRL("email"), alloc),
            STRL("data@datadoghq.com"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto rule = read_json_file("postprocessor.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(values, STRL("email"), alloc),
            STRL("data@datadoghq.com"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);
        EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0), R"([{"email":[8]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, ScannerUpdate)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_destroy(&scanner, alloc);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(values, STRL("email"), alloc),
            STRL("data@datadoghq.com"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto scanner = json_to_object(
            R"({"scanners":[{"id":"scanner-002","value":{"operator":"match_regex","parameters":{"regex":"notanemail","options":{"case_sensitive":false,"min_length":1}}},"tags":{"type":"email","category":"pii"}}]})");
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_destroy(&scanner, alloc);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(values, STRL("email"), alloc), STRL("notanemail"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, ProcessorAndScannerUpdate)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_destroy(&scanner, alloc);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(values, STRL("email"), alloc),
            STRL("data@datadoghq.com"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto rule = read_json_file("processor_with_scanner_by_id.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(values, STRL("email"), alloc),
            STRL("data@datadoghq.com"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, EmptyScannerUpdate)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_destroy(&scanner, alloc);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(values, STRL("email"), alloc),
            STRL("data@datadoghq.com"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("scanners"));
    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(values, STRL("email"), alloc),
            STRL("data@datadoghq.com"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);
        EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0), R"([{"email":[8]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, EmptyProcessorUpdate)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_destroy(&scanner, alloc);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(values, STRL("email"), alloc),
            STRL("data@datadoghq.com"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_at_value(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);
        auto rule = json_to_object(
            R"({"version": "2.2", "metadata": {"rules_version": "1.8.0"}, "rules": [{"id": "rule1", "name": "rule1", "tags": {"type": "flow1", "category": "category1"}, "conditions": [{"parameters": {"inputs": [{"address": "server.request.body.schema"}], "value": 8, "type": "unsigned"}, "operator": "equals"}]}], "processors": []})");
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *values = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(values, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(values, STRL("email"), alloc),
            STRL("data@datadoghq.com"), alloc);

        auto *settings = ddwaf_object_insert_key(&map, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, PostprocessorWithSubcontextMapping)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 2);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object persistent;
    ddwaf_object_set_map(&persistent, 2, alloc);
    auto *settings = ddwaf_object_insert_key(&persistent, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);
    ASSERT_EQ(ddwaf_context_eval(context, &persistent, alloc, nullptr, LONG_TIME), DDWAF_OK);

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("server.request.body"), alloc), STRL("value"),
            alloc);

        auto *subctx = ddwaf_subcontext_init(context);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);

        auto *nested_map = ddwaf_object_insert_key(&ephemeral, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(nested_map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(nested_map, STRL("key"), alloc), STRL("value"), alloc);

        auto *subctx = ddwaf_subcontext_init(context);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"key":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, PreprocessorWithSubcontextMapping)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 3);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.body.schema"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object persistent;
    ddwaf_object_set_map(&persistent, 1, alloc);
    auto *settings = ddwaf_object_insert_key(&persistent, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ASSERT_EQ(ddwaf_context_eval(context, &persistent, alloc, nullptr, LONG_TIME), DDWAF_OK);

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("server.request.body"), alloc), STRL("value"),
            alloc);

        auto *subctx = ddwaf_subcontext_init(context);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        EXPECT_EVENTS(out, {.id = "rule1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "equals",
                                   .op_value = "",
                                   .highlight = ""sv,
                                   .args = {{
                                       .value = "8"sv,
                                       .address = "server.request.body.schema",
                                       .path = {0},
                                   }}}}});

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

        ddwaf_object_destroy(&out, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("server.request.body"), alloc), STRL("value"),
            alloc);

        auto *subctx = ddwaf_subcontext_init(context);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        EXPECT_EVENTS(out, {.id = "rule1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "equals",
                                   .op_value = "",
                                   .highlight = ""sv,
                                   .args = {{
                                       .value = "8"sv,
                                       .address = "server.request.body.schema",
                                       .path = {0},
                                   }}}}});

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

        ddwaf_object_destroy(&out, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ProcessorSubcontextExpression)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 4);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.body.schema"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object persistent;
        ddwaf_object_set_map(&persistent, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&persistent, STRL("server.request.query"), alloc),
            STRL("value"), alloc);
        ASSERT_EQ(ddwaf_context_eval(context, &persistent, alloc, nullptr, LONG_TIME), DDWAF_OK);
    }

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);

        auto *settings = ddwaf_object_insert_key(&ephemeral, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        auto *subctx = ddwaf_subcontext_init(context);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.query.schema":[8]})");

        ddwaf_subcontext_destroy(subctx);
        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object persistent;
        ddwaf_object_set_map(&persistent, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&persistent, STRL("server.request.body"), alloc), STRL("value"),
            alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &persistent, alloc, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

        ddwaf_object_destroy(&out, alloc);
    }

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);

        auto *settings = ddwaf_object_insert_key(&ephemeral, STRL("waf.context.processor"), alloc);
        ddwaf_object_set_map(settings, 1, alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

        auto *subctx = ddwaf_subcontext_init(context);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        EXPECT_EVENTS(out, {.id = "rule1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "equals",
                                   .op_value = "",
                                   .highlight = ""sv,
                                   .args = {{
                                       .value = "8"sv,
                                       .address = "server.request.body.schema",
                                       .path = {0},
                                   }}}}});

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 2);

        // The attribute collector orders entries via an unordered_map, so the
        // serialised key order is unspecified; compare structurally.
        EXPECT_JSON(
            *attributes, R"({"server.request.body.schema":[8],"server.request.query.schema":[8]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

namespace preprocessor_chain {

// Two preprocessors, the second consuming the output of the first, and a rule
// on the output of the second. Processors are evaluated in an order which
// depends on the implementation, so both listing orders are tested.
ddwaf_handle init_chain(bool consumer_first)
{
    const std::string producer =
        R"({"id": "producer", "generator": "extract_schema", "parameters": {"mappings":
        [{"inputs": [{"address": "server.request.body"}], "output": "x.schema1"}]},
        "evaluate": true, "output": false})";
    const std::string consumer =
        R"({"id": "consumer", "generator": "extract_schema", "parameters": {"mappings":
        [{"inputs": [{"address": "x.schema1"}], "output": "x.schema2"}]},
        "evaluate": true, "output": false})";
    const auto processors =
        consumer_first ? consumer + "," + producer : producer + "," + consumer;

    auto rule = json_to_object(
        R"({"version": "2.2", "metadata": {"rules_version": "1.8.0"}, "rules": [
        {"id": "rule1", "name": "rule1", "tags": {"type": "flow1", "category": "category1"},
        "conditions": [{"operator": "exists", "parameters": {"inputs": [{"address":
        "x.schema2"}]}}]}], "processors": [)" +
        processors + "]}");
    auto *handle = ddwaf_init(&rule, nullptr);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());
    return handle;
}

DDWAF_RET_CODE eval(ddwaf_context context, std::string_view address)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    auto *value = ddwaf_object_insert_key(&map, address.data(), address.size(), alloc);
    ddwaf_object_set_map(value, 1, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("a"), alloc), STRL("b"), alloc);

    ddwaf_object out;
    auto code = ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
    ddwaf_object_destroy(&out, alloc);
    return code;
}

DDWAF_RET_CODE eval(ddwaf_subcontext subcontext, std::string_view address)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    auto *value = ddwaf_object_insert_key(&map, address.data(), address.size(), alloc);
    ddwaf_object_set_map(value, 1, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("a"), alloc), STRL("b"), alloc);

    ddwaf_object out;
    auto code = ddwaf_subcontext_eval(subcontext, &map, alloc, &out, LONG_TIME);
    ddwaf_object_destroy(&out, alloc);
    return code;
}

} // namespace preprocessor_chain

TEST(TestExtractSchemaIntegration, PreprocessorChainInLaterContextEval)
{
    auto *alloc = ddwaf_get_default_allocator();
    unsigned matches = 0;
    for (bool consumer_first : {false, true}) {
        auto *handle = preprocessor_chain::init_chain(consumer_first);
        ASSERT_NE(handle, nullptr);

        // The first evaluation runs both preprocessors without input, the
        // second must run the consumer on the output of the producer if the
        // latter is evaluated first.
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);
        EXPECT_EQ(preprocessor_chain::eval(context, "unrelated"), DDWAF_OK);
        if (preprocessor_chain::eval(context, "server.request.body") == DDWAF_MATCH) {
            ++matches;
        }
        ddwaf_context_destroy(context);

        ddwaf_destroy(handle);
    }
    // The order of evaluation of the processors depends on the
    // implementation, but one of the listing orders evaluates the producer
    // first.
    EXPECT_GE(matches, 1);
}

TEST(TestExtractSchemaIntegration, PreprocessorChainInSubcontext)
{
    auto *alloc = ddwaf_get_default_allocator();
    unsigned matches = 0;
    for (bool consumer_first : {false, true}) {
        auto *handle = preprocessor_chain::init_chain(consumer_first);
        ASSERT_NE(handle, nullptr);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);
        EXPECT_EQ(preprocessor_chain::eval(context, "unrelated"), DDWAF_OK);

        ddwaf_subcontext subcontext = ddwaf_subcontext_init(context);
        ASSERT_NE(subcontext, nullptr);
        if (preprocessor_chain::eval(subcontext, "server.request.body") == DDWAF_MATCH) {
            ++matches;
        }
        ddwaf_subcontext_destroy(subcontext);

        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
    }
    // See PreprocessorChainInLaterContextEval
    EXPECT_GE(matches, 1);
}

} // namespace
