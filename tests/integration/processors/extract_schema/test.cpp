// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../../test_utils.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/processors/extract_schema";

TEST(TestExtractSchemaIntegration, Postprocessor)
{
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
    EXPECT_FALSE(out.timeout);

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

    auto schema = test::object_to_json(out.derivatives);
    EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, Preprocessor)
{
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "equals",
                               .op_value = "",
                               .highlight = "",
                               .args = {{
                                   .value = "8",
                                   .address = "server.request.body.schema",
                                   .path = {"0"},
                               }}}}});

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 0);

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, Processor)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "equals",
                               .op_value = "",
                               .highlight = "",
                               .args = {{
                                   .value = "8",
                                   .address = "server.request.body.schema",
                                   .path = {"0"},
                               }}}}});

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

    auto schema = test::object_to_json(out.derivatives);
    EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ProcessorWithScannerByTags)
{
    auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

    ddwaf_result out;
    ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
    EXPECT_FALSE(out.timeout);
    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

    EXPECT_SCHEMA_EQ(
        out.derivatives.array[0], R"([{"email":[8,{"category":"pii","type":"email"}]}])");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ProcessorWithScannerByID)
{
    auto rule = read_json_file("processor_with_scanner_by_id.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

    ddwaf_result out;
    ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
    EXPECT_FALSE(out.timeout);
    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

    EXPECT_SCHEMA_EQ(
        out.derivatives.array[0], R"([{"email":[8,{"category":"pii","type":"email"}]}])");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);

    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ProcessorUpdate)
{
    auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        EXPECT_SCHEMA_EQ(
            out.derivatives.array[0], R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto new_ruleset = read_json_file("postprocessor.json", base_dir);
        auto *new_handle = ddwaf_update(handle, &new_ruleset, nullptr, nullptr);
        ddwaf_object_free(&new_ruleset);
        ddwaf_destroy(handle);

        handle = new_handle;
    }

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        EXPECT_SCHEMA_EQ(out.derivatives.array[0], R"([{"email":[8]}])");

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ScannerUpdate)
{
    auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        EXPECT_SCHEMA_EQ(
            out.derivatives.array[0], R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto new_scanners = json_to_object(
            R"({"scanners":[{"id":"scanner-002","value":{"operator":"match_regex","parameters":{"regex":"notanemail","options":{"case_sensitive":false,"min_length":1}}},"tags":{"type":"email","category":"pii"}}]})");
        auto *new_handle = ddwaf_update(handle, &new_scanners, nullptr, nullptr);
        ddwaf_object_free(&new_scanners);
        ddwaf_destroy(handle);

        handle = new_handle;
    }

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        EXPECT_SCHEMA_EQ(
            out.derivatives.array[0], R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ProcessorAndScannerUpdate)
{
    auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        EXPECT_SCHEMA_EQ(
            out.derivatives.array[0], R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto new_ruleset = read_json_file("processor_with_scanner_by_id.json", base_dir);
        auto *new_handle = ddwaf_update(handle, &new_ruleset, nullptr, nullptr);
        ddwaf_object_free(&new_ruleset);
        ddwaf_destroy(handle);

        handle = new_handle;
    }

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        EXPECT_SCHEMA_EQ(
            out.derivatives.array[0], R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, EmptyScannerUpdate)
{
    auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        EXPECT_SCHEMA_EQ(
            out.derivatives.array[0], R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto new_ruleset = json_to_object(R"({"scanners":[]})");
        auto *new_handle = ddwaf_update(handle, &new_ruleset, nullptr, nullptr);
        ddwaf_object_free(&new_ruleset);
        ddwaf_destroy(handle);

        handle = new_handle;
    }

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        EXPECT_SCHEMA_EQ(out.derivatives.array[0], R"([{"email":[8]}])");

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, EmptyProcessorUpdate)
{
    auto rule = read_json_file("processor_with_scanner_by_tags.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        EXPECT_SCHEMA_EQ(
            out.derivatives.array[0], R"([{"email":[8,{"category":"pii","type":"email"}]}])");

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto new_ruleset = json_to_object(R"({"processors":[]})");
        auto *new_handle = ddwaf_update(handle, &new_ruleset, nullptr, nullptr);
        ddwaf_object_free(&new_ruleset);
        ddwaf_destroy(handle);

        handle = new_handle;
    }

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

        ddwaf_result out;
        ddwaf_run(context, &map, nullptr, &out, LONG_TIME);
        EXPECT_FALSE(out.timeout);
        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 0);

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, PostprocessorWithEphemeralMapping)
{
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
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

        ddwaf_result out;
        ASSERT_EQ(ddwaf_run(context, &persistent, &ephemeral, &out, LONG_TIME), DDWAF_OK);
        EXPECT_FALSE(out.timeout);

        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        auto schema = test::object_to_json(out.derivatives);
        EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

        ddwaf_result_free(&out);
    }

    {
        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_string(&value, "value");
        ddwaf_object_map_add(&map, "key", &value);
        ddwaf_object_map_add(&ephemeral, "server.request.body", &map);

        ddwaf_result out;
        ASSERT_EQ(ddwaf_run(context, nullptr, &ephemeral, &out, LONG_TIME), DDWAF_OK);
        EXPECT_FALSE(out.timeout);

        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        auto schema = test::object_to_json(out.derivatives);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"key":[8]}]})");

        ddwaf_result_free(&out);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, PreprocessorWithEphemeralMapping)
{
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
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

        ddwaf_result out;
        ASSERT_EQ(ddwaf_run(context, &persistent, &ephemeral, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_FALSE(out.timeout);

        EXPECT_EVENTS(out, {.id = "rule1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "equals",
                                   .op_value = "",
                                   .highlight = "",
                                   .args = {{
                                       .value = "8",
                                       .address = "server.request.body.schema",
                                       .path = {"0"},
                                   }}}}});

        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 0);

        ddwaf_result_free(&out);
    }

    {
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_string(&value, "value");
        ddwaf_object_map_add(&ephemeral, "server.request.body", &value);

        ddwaf_result out;
        ASSERT_EQ(ddwaf_run(context, nullptr, &ephemeral, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_FALSE(out.timeout);

        EXPECT_EVENTS(out, {.id = "rule1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "equals",
                                   .op_value = "",
                                   .highlight = "",
                                   .args = {{
                                       .value = "8",
                                       .address = "server.request.body.schema",
                                       .path = {"0"},
                                   }}}}});

        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 0);

        ddwaf_result_free(&out);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExtractSchemaIntegration, ProcessorEphemeralExpression)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
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

        ddwaf_result out;
        ASSERT_EQ(ddwaf_run(context, &persistent, &ephemeral, &out, LONG_TIME), DDWAF_OK);
        EXPECT_FALSE(out.timeout);

        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        auto schema = test::object_to_json(out.derivatives);
        EXPECT_STR(schema, R"({"server.request.query.schema":[8]})");

        ddwaf_result_free(&out);
    }

    {
        ddwaf_object persistent = DDWAF_OBJECT_MAP;
        ddwaf_object_string(&value, "value");
        ddwaf_object_map_add(&persistent, "server.request.body", &value);

        ddwaf_result out;
        ASSERT_EQ(ddwaf_run(context, &persistent, nullptr, &out, LONG_TIME), DDWAF_OK);
        EXPECT_FALSE(out.timeout);

        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 0);

        ddwaf_result_free(&out);
    }

    {
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object settings = DDWAF_OBJECT_MAP;
        ddwaf_object_bool(&value, true);
        ddwaf_object_map_add(&settings, "extract-schema", &value);
        ddwaf_object_map_add(&ephemeral, "waf.context.processor", &settings);

        ddwaf_result out;
        ASSERT_EQ(ddwaf_run(context, nullptr, &ephemeral, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_FALSE(out.timeout);

        EXPECT_EVENTS(out, {.id = "rule1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "equals",
                                   .op_value = "",
                                   .highlight = "",
                                   .args = {{
                                       .value = "8",
                                       .address = "server.request.body.schema",
                                       .path = {"0"},
                                   }}}}});

        EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

        auto schema = test::object_to_json(out.derivatives);
        EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

        ddwaf_result_free(&out);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
