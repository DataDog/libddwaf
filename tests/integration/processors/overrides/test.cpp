// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/raw_configuration.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/processors/overrides";

TEST(TestProcessorOverridesIntegration, AddScannersById)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id": "scanner-001"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, AddScannersByTags)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags": {"type":"email"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, AddScannerToPopulatedProcessor)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.headers.schema":[{"email":[8,{"type":"token","category":"credential"}]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"include": [{"id": "scanner-001"}], "exclude": [{"id": "scanner-002"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override1"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.headers.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"exclude": [{"id": "scanner-001"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override2"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.headers.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, DisableDefaultScanners)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.headers.schema":[{"email":[8,{"type":"token","category":"credential"}]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"exclude": [{"tags": {"type":"token"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.headers.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, RemoveScannersAfterOverride)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id": "scanner-001"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("scanners"));

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, RemoveOverride)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id": "scanner-001"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("override"));

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, OverrideMultipleProcessors)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 2);
        ddwaf::raw_configuration derivatives_object(*attributes);
        auto derivatives = static_cast<ddwaf::raw_configuration::map>(derivatives_object);

        auto headers_schema = test::object_to_json(derivatives["server.request.headers.schema"]);
        EXPECT_STR(headers_schema, R"([{"email":[8,{"type":"token","category":"credential"}]}])");

        auto body_schema = test::object_to_json(derivatives["server.request.body.schema"]);
        EXPECT_STR(body_schema, R"([{"email":[8]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"},{"id":"extract-headers"}], "scanners": {"include": [{"id":"scanner-001"}], "exclude": [{"tags": {"type": "token"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 2);

        EXPECT_EQ(ddwaf_object_size(attributes), 2);
        ddwaf::raw_configuration derivatives_object(*attributes);
        auto derivatives = static_cast<ddwaf::raw_configuration::map>(derivatives_object);

        auto headers_schema = test::object_to_json(derivatives["server.request.headers.schema"]);
        EXPECT_STR(headers_schema, R"([{"email":[8,{"type":"email","category":"pii"}]}])");

        auto body_schema = test::object_to_json(derivatives["server.request.body.schema"]);
        EXPECT_STR(body_schema, R"([{"email":[8,{"type":"email","category":"pii"}]}])");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, ScannersPrecedenceIdVsTagsOnEmptyProcessor)
{
    // Scenario A: include by tags, exclude by ID (exclude wins)
    {
        auto *builder = ddwaf_builder_init(nullptr);
        ASSERT_NE(builder, nullptr);

        auto processors = read_json_file("processors.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
        ddwaf_object_free(&processors);

        auto scanners = read_json_file("scanners.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
        ddwaf_object_free(&scanners);

        auto ovrd = json_to_object(
            R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags": {"type":"email"}}], "exclude": [{"id":"scanner-001"}]}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
        ddwaf_object_free(&ovrd);

        auto *handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }

    // Scenario B: include by ID, exclude by tags (include ID wins)
    {
        auto *builder = ddwaf_builder_init(nullptr);
        ASSERT_NE(builder, nullptr);

        auto processors = read_json_file("processors.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
        ddwaf_object_free(&processors);

        auto scanners = read_json_file("scanners.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
        ddwaf_object_free(&scanners);

        auto ovrd = json_to_object(
            R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id":"scanner-001"}], "exclude": [{"tags": {"type":"email"}}]}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
        ddwaf_object_free(&ovrd);

        auto *handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }

    // Scenario C: include by tags and exclude by tags (exclude tags wins)
    {
        auto *builder = ddwaf_builder_init(nullptr);
        ASSERT_NE(builder, nullptr);

        auto processors = read_json_file("processors.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
        ddwaf_object_free(&processors);

        auto scanners = read_json_file("scanners.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
        ddwaf_object_free(&scanners);

        auto ovrd = json_to_object(
            R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags": {"type":"email"}}], "exclude": [{"tags": {"type":"email"}}]}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
        ddwaf_object_free(&ovrd);

        auto *handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }

    // Scenario D: include by ID and exclude by ID (exclude ID wins)
    {
        auto *builder = ddwaf_builder_init(nullptr);
        ASSERT_NE(builder, nullptr);

        auto processors = read_json_file("processors.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
        ddwaf_object_free(&processors);

        auto scanners = read_json_file("scanners.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
        ddwaf_object_free(&scanners);

        auto ovrd = json_to_object(
            R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id":"scanner-001"}], "exclude": [{"id":"scanner-001"}]}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
        ddwaf_object_free(&ovrd);

        auto *handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.body", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }
}

TEST(TestProcessorOverridesIntegration, ScannersPrecedenceOnDefaultProcessor)
{
    // Start from processor with default tag-based scanners (headers -> token/credential)
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    // include token by tags but exclude its ID -> exclude ID wins, so removed
    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"include": [{"tags": {"type":"token"}}], "exclude": [{"id":"scanner-002"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.headers.schema":[{"email":[8]}]})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, IncludeMultipleScannersById)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id":"scanner-001"},{"id":"scanner-003"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;
    ddwaf_object value;
    ddwaf_object map = DDWAF_OBJECT_MAP;

    ddwaf_object_map(&value);
    ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
    ddwaf_object_map_add(&value, "api_key", ddwaf_object_string(&tmp, "sk_live_1234567890abcdef"));
    ddwaf_object_map_add(&map, "server.request.body", &value);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_size(attributes), 1);

    ddwaf::raw_configuration derivatives_object(*attributes);
    auto derivatives = static_cast<ddwaf::raw_configuration::map>(derivatives_object);
    auto body_schema = test::object_to_json(derivatives["server.request.body.schema"]);
    EXPECT_NE(
        body_schema.find(R"("email":[8,{"type":"email","category":"pii"}])"), std::string::npos);
    EXPECT_NE(body_schema.find(R"("api_key":[8,{"type":"api_key","category":"auth"}])"),
        std::string::npos);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, IncludeMultipleScannersByTags)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags":{"type":"email"}},{"tags":{"type":"api_key"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;
    ddwaf_object value;
    ddwaf_object map = DDWAF_OBJECT_MAP;

    ddwaf_object_map(&value);
    ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
    ddwaf_object_map_add(&value, "api_key", ddwaf_object_string(&tmp, "sk_live_1234567890abcdef"));
    ddwaf_object_map_add(&map, "server.request.body", &value);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_size(attributes), 1);

    ddwaf::raw_configuration derivatives_object(*attributes);
    auto derivatives = static_cast<ddwaf::raw_configuration::map>(derivatives_object);
    auto body_schema = test::object_to_json(derivatives["server.request.body.schema"]);
    EXPECT_NE(
        body_schema.find(R"("email":[8,{"type":"email","category":"pii"}])"), std::string::npos);
    EXPECT_NE(body_schema.find(R"("api_key":[8,{"type":"api_key","category":"auth"}])"),
        std::string::npos);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, IncludeThenExcludeMultipleScannersByIdOnHeaders)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    // First, include both by ID
    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"include": [{"id":"scanner-001"},{"id":"scanner-003"}], "exclude": [{"tags": {"category": "credential"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override1"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(
            &value, "api_key", ddwaf_object_string(&tmp, "sk_live_1234567890abcdef"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        ddwaf::raw_configuration derivatives_object(*attributes);
        auto derivatives = static_cast<ddwaf::raw_configuration::map>(derivatives_object);
        auto headers_schema = test::object_to_json(derivatives["server.request.headers.schema"]);
        EXPECT_NE(headers_schema.find(R"("email":[8,{"type":"email","category":"pii"}])"),
            std::string::npos);
        EXPECT_NE(headers_schema.find(R"("api_key":[8,{"type":"api_key","category":"auth"}])"),
            std::string::npos);

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    // Then, exclude both by ID; excluded by ID wins, leaving none
    ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"exclude": [{"id":"scanner-001"},{"id":"scanner-003"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override2"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object tmp;
        ddwaf_object value;
        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object_map(&value);
        ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
        ddwaf_object_map_add(
            &value, "api_key", ddwaf_object_string(&tmp, "sk_live_1234567890abcdef"));
        ddwaf_object_map_add(&map, "server.request.headers", &value);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        ddwaf::raw_configuration derivatives_object(*attributes);
        auto derivatives = static_cast<ddwaf::raw_configuration::map>(derivatives_object);
        auto headers_schema = test::object_to_json(derivatives["server.request.headers.schema"]);
        EXPECT_NE(headers_schema.find(R"("email":[8])"), std::string::npos);
        EXPECT_NE(headers_schema.find(R"("api_key":[8])"), std::string::npos);
        EXPECT_EQ(headers_schema.find(R"({"type":"email","category":"pii"})"), std::string::npos);
        EXPECT_EQ(
            headers_schema.find(R"({"type":"api_key","category":"auth"})"), std::string::npos);

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, IncludeMultipleByTagsExcludeOneById)
{
    auto *builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_free(&processors);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_free(&scanners);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags":{"type":"email"}},{"tags":{"type":"api_key"}}], "exclude": [{"id":"scanner-003"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_free(&ovrd);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;
    ddwaf_object value;
    ddwaf_object map = DDWAF_OBJECT_MAP;

    ddwaf_object_map(&value);
    ddwaf_object_map_add(&value, "email", ddwaf_object_string(&tmp, "employee@company.com"));
    ddwaf_object_map_add(&value, "api_key", ddwaf_object_string(&tmp, "sk_live_1234567890abcdef"));
    ddwaf_object_map_add(&map, "server.request.body", &value);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_size(attributes), 1);

    ddwaf::raw_configuration derivatives_object(*attributes);
    auto derivatives = static_cast<ddwaf::raw_configuration::map>(derivatives_object);
    auto body_schema = test::object_to_json(derivatives["server.request.body.schema"]);
    EXPECT_NE(
        body_schema.find(R"("email":[8,{"type":"email","category":"pii"}])"), std::string::npos);
    EXPECT_NE(body_schema.find(R"("api_key":[8])"), std::string::npos);
    EXPECT_EQ(body_schema.find(R"("type":"api_key","category":"auth")"), std::string::npos);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

} // namespace
