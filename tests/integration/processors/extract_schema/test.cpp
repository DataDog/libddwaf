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
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 2);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object value;

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_string(&value, "value");
    ddwaf_object_map_add(&map, "server.request.body", &value);

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_size(attributes), 1);

    auto schema = test::object_to_json(*attributes);
    EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, Preprocessor)
{
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 3);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.body.schema"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object value;

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_string(&value, "value");
    ddwaf_object_map_add(&map, "server.request.body", &value);

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
                                   .path = {"0"},
                               }}}}});

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_size(attributes), 0);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, Processor)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 4);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.body.schema"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object value;

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_string(&value, "value");
    ddwaf_object_map_add(&map, "server.request.body", &value);

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
                                   .path = {"0"},
                               }}}}});

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_size(attributes), 1);

    auto schema = test::object_to_json(*attributes);
    EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ProcessorWithScannerByTags)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
    ddwaf_object_free(&rule);

    auto scanner = read_json_file("scanners.json", base_dir);
    ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
    ddwaf_object_free(&scanner);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object value;
    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object values = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_string(&value, "data@datadoghq.com");
    ddwaf_object_map_add(&values, "email", &value);
    ddwaf_object_map_add(&map, "server.request.body", &values);

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object out;
    ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_size(attributes), 1);
    EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0),
        R"([{"email":[8,{"category":"pii","type":"email"}]}])");

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);

    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, ProcessorWithScannerByID)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = read_json_file("processor_with_scanner_by_id.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
    ddwaf_object_free(&rule);

    auto scanner = read_json_file("scanners.json", base_dir);
    ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
    ddwaf_object_free(&scanner);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object value;
    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object values = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_string(&value, "data@datadoghq.com");
    ddwaf_object_map_add(&values, "email", &value);
    ddwaf_object_map_add(&map, "server.request.body", &values);

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object out;
    ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_size(attributes), 1);
    EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0),
        R"([{"email":[8,{"category":"pii","type":"email"}]}])");

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, ProcessorUpdate)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_free(&scanner);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object value;

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "data@datadoghq.com");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto rule = read_json_file("postprocessor.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "data@datadoghq.com");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);
        EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0), R"([{"email":[8]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, ScannerUpdate)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_free(&scanner);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object value;

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "data@datadoghq.com");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto scanner = json_to_object(
            R"({"scanners":[{"id":"scanner-002","value":{"operator":"match_regex","parameters":{"regex":"notanemail","options":{"case_sensitive":false,"min_length":1}}},"tags":{"type":"email","category":"pii"}}]})");
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_free(&scanner);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "notanemail");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, ProcessorAndScannerUpdate)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_free(&scanner);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object value;

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "data@datadoghq.com");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);

        auto rule = read_json_file("processor_with_scanner_by_id.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "data@datadoghq.com");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, EmptyScannerUpdate)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_free(&scanner);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object value;

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "data@datadoghq.com");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("scanners"));
    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "data@datadoghq.com");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);
        EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0), R"([{"email":[8]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, EmptyProcessorUpdate)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);

        auto scanner = read_json_file("scanners.json", base_dir);
        ASSERT_NE(scanner.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanner, nullptr);
        ddwaf_object_free(&scanner);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_object value;

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "data@datadoghq.com");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        EXPECT_SCHEMA_EQ(*ddwaf_object_get_index(attributes, 0),
            R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_destroy(handle);
        auto rule = json_to_object(
            R"({"version": "2.2", "metadata": {"rules_version": "1.8.0"}, "rules": [{"id": "rule1", "name": "rule1", "tags": {"type": "flow1", "category": "category1"}, "conditions": [{"parameters": {"inputs": [{"address": "server.request.body.schema"}], "value": 8, "type": "unsigned"}, "operator": "equals"}]}], "processors": []})");
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object values = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;

        ddwaf_object_string(&value, "data@datadoghq.com");
        ddwaf_object_map_add(&values, "email", &value);
        ddwaf_object_map_add(&map, "server.request.body", &values);

        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&map, "waf.context.processor", &settings);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 0);

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExtractSchemaIntegration, PostprocessorWithEphemeralMapping)
{
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 2);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object value;

    ddwaf_object persistent = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&persistent, "waf.context.processor", &settings);

    {
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_string(&value, "value");
        ddwaf_object_map_add(&ephemeral, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &persistent, &ephemeral, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_string(&value, "value");
        ddwaf_object_map_add(&map, "key", &value);
        ddwaf_object_map_add(&ephemeral, "server.request.body", &map);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, nullptr, &ephemeral, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"key":[8]}]})");

        ddwaf_object_free(&out);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, PreprocessorWithEphemeralMapping)
{
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 3);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.body.schema"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object value;

    ddwaf_object persistent = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&persistent, "waf.context.processor", &settings);

    {
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_string(&value, "value");
        ddwaf_object_map_add(&ephemeral, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &persistent, &ephemeral, &out, LONG_TIME), DDWAF_MATCH);
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
                                       .path = {"0"},
                                   }}}}});

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 0);

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_string(&value, "value");
        ddwaf_object_map_add(&ephemeral, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, nullptr, &ephemeral, &out, LONG_TIME), DDWAF_MATCH);
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
                                       .path = {"0"},
                                   }}}}});

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 0);

        ddwaf_object_free(&out);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ProcessorEphemeralExpression)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_known_addresses(handle, &size);
    EXPECT_EQ(size, 4);
    std::unordered_set<std::string_view> address_set(addresses, addresses + size);
    EXPECT_TRUE(address_set.contains("server.request.body"));
    EXPECT_TRUE(address_set.contains("server.request.body.schema"));
    EXPECT_TRUE(address_set.contains("server.request.query"));
    EXPECT_TRUE(address_set.contains("waf.context.processor"));

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object value;

    {
        ddwaf_object persistent = DDWAF_OBJECT_MAP;
        ddwaf_object_string(&value, "value");
        ddwaf_object_map_add(&persistent, "server.request.query", &value);

        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;
        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&ephemeral, "waf.context.processor", &settings);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &persistent, &ephemeral, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.query.schema":[8]})");

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object persistent = DDWAF_OBJECT_MAP;
        ddwaf_object_string(&value, "value");
        ddwaf_object_map_add(&persistent, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &persistent, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 0);

        ddwaf_object_free(&out);
    }

    {
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;
        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&ephemeral, "waf.context.processor", &settings);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, nullptr, &ephemeral, &out, LONG_TIME), DDWAF_MATCH);
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
                                       .path = {"0"},
                                   }}}}});

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

        ddwaf_object_free(&out);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
