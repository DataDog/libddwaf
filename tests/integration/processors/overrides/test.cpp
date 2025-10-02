// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "common/json_utils.hpp"
#include "configuration/common/raw_configuration.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/processors/overrides";

TEST(TestProcessorOverridesIntegration, AddScannersById)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id": "scanner-001"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, AddScannersByTags)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags": {"type":"email"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, AddScannerToPopulatedProcessor)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.headers.schema":[{"email":[8,{"type":"token","category":"credential"}]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"include": [{"id": "scanner-001"}], "exclude": [{"id": "scanner-002"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override1"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.headers.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"exclude": [{"id": "scanner-001"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override2"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.headers.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, DisableDefaultScanners)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.headers.schema":[{"email":[8,{"type":"token","category":"credential"}]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"exclude": [{"tags": {"type":"token"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.headers.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, RemoveScannersAfterOverride)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id": "scanner-001"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("scanners"));

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, RemoveOverride)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id": "scanner-001"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("override"));

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, OverrideMultipleProcessors)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 2);
        ddwaf::raw_configuration derivatives_object(
            *reinterpret_cast<const detail::object *>(attributes));
        auto derivatives = static_cast<ddwaf::raw_configuration::map>(derivatives_object);

        auto headers_schema =
            test::object_to_json(derivatives["server.request.headers.schema"]->ref());
        EXPECT_STR(headers_schema, R"([{"email":[8,{"type":"token","category":"credential"}]}])");

        auto body_schema = test::object_to_json(derivatives["server.request.body.schema"]->ref());
        EXPECT_STR(body_schema, R"([{"email":[8]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"},{"id":"extract-headers"}], "scanners": {"include": [{"id":"scanner-001"}], "exclude": [{"tags": {"type": "token"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 2, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 2);

        EXPECT_EQ(ddwaf_object_get_size(attributes), 2);
        ddwaf::raw_configuration derivatives_object(
            *reinterpret_cast<const detail::object *>(attributes));
        auto derivatives = static_cast<ddwaf::raw_configuration::map>(derivatives_object);

        auto headers_schema =
            test::object_to_json(derivatives["server.request.headers.schema"]->ref());
        EXPECT_STR(headers_schema, R"([{"email":[8,{"type":"email","category":"pii"}]}])");

        auto body_schema = test::object_to_json(derivatives["server.request.body.schema"]->ref());
        EXPECT_STR(body_schema, R"([{"email":[8,{"type":"email","category":"pii"}]}])");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, ScannersPrecedenceIdVsTagsOnEmptyProcessor)
{
    auto *alloc = ddwaf_get_default_allocator();

    // Scenario A: include by tags, exclude by ID (exclude wins)
    {
        auto *builder = ddwaf_builder_init();
        ASSERT_NE(builder, nullptr);

        auto processors = read_json_file("processors.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
        ddwaf_object_destroy(&processors, alloc);

        auto scanners = read_json_file("scanners.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
        ddwaf_object_destroy(&scanners, alloc);

        auto ovrd = json_to_object(
            R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags": {"type":"email"}}], "exclude": [{"id":"scanner-001"}]}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
        ddwaf_object_destroy(&ovrd, alloc);

        auto *handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }

    // Scenario B: include by ID, exclude by tags (include ID wins)
    {
        auto *builder = ddwaf_builder_init();
        ASSERT_NE(builder, nullptr);

        auto processors = read_json_file("processors.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
        ddwaf_object_destroy(&processors, alloc);

        auto scanners = read_json_file("scanners.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
        ddwaf_object_destroy(&scanners, alloc);

        auto ovrd = json_to_object(
            R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id":"scanner-001"}], "exclude": [{"tags": {"type":"email"}}]}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
        ddwaf_object_destroy(&ovrd, alloc);

        auto *handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema,
            R"({"server.request.body.schema":[{"email":[8,{"type":"email","category":"pii"}]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }

    // Scenario C: include by tags and exclude by tags (exclude tags wins)
    {
        auto *builder = ddwaf_builder_init();
        ASSERT_NE(builder, nullptr);

        auto processors = read_json_file("processors.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
        ddwaf_object_destroy(&processors, alloc);

        auto scanners = read_json_file("scanners.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
        ddwaf_object_destroy(&scanners, alloc);

        auto ovrd = json_to_object(
            R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags": {"type":"email"}}], "exclude": [{"tags": {"type":"email"}}]}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
        ddwaf_object_destroy(&ovrd, alloc);

        auto *handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }

    // Scenario D: include by ID and exclude by ID (exclude ID wins)
    {
        auto *builder = ddwaf_builder_init();
        ASSERT_NE(builder, nullptr);

        auto processors = read_json_file("processors.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
        ddwaf_object_destroy(&processors, alloc);

        auto scanners = read_json_file("scanners.json", base_dir);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
        ddwaf_object_destroy(&scanners, alloc);

        auto ovrd = json_to_object(
            R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id":"scanner-001"}], "exclude": [{"id":"scanner-001"}]}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
        ddwaf_object_destroy(&ovrd, alloc);

        auto *handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.body.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }
}

TEST(TestProcessorOverridesIntegration, ScannersPrecedenceOnDefaultProcessor)
{
    auto *alloc = ddwaf_get_default_allocator();

    // Start from processor with default tag-based scanners (headers -> token/credential)
    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    // include token by tags but exclude its ID -> exclude ID wins, so removed
    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"include": [{"tags": {"type":"token"}}], "exclude": [{"id":"scanner-002"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto schema = test::object_to_json(*attributes);
        EXPECT_STR(schema, R"({"server.request.headers.schema":[{"email":[8]}]})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, IncludeMultipleScannersById)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"id":"scanner-001"},{"id":"scanner-003"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);

    auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_map(value, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(value, STRL("email"), alloc), STRL("employee@company.com"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("api_key"), alloc),
        STRL("sk_live_1234567890abcdef"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    auto body_schema =
        test::object_to_json(*ddwaf_object_find(attributes, STRL("server.request.body.schema")));
    EXPECT_NE(
        body_schema.find(R"("email":[8,{"type":"email","category":"pii"}])"), std::string::npos);
    EXPECT_NE(body_schema.find(R"("api_key":[8,{"type":"api_key","category":"auth"}])"),
        std::string::npos);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, IncludeMultipleScannersByTags)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags":{"type":"email"}},{"tags":{"type":"api_key"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);

    auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_map(value, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(value, STRL("email"), alloc), STRL("employee@company.com"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("api_key"), alloc),
        STRL("sk_live_1234567890abcdef"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    auto body_schema =
        test::object_to_json(*ddwaf_object_find(attributes, STRL("server.request.body.schema")));
    EXPECT_NE(
        body_schema.find(R"("email":[8,{"type":"email","category":"pii"}])"), std::string::npos);
    EXPECT_NE(body_schema.find(R"("api_key":[8,{"type":"api_key","category":"auth"}])"),
        std::string::npos);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, IncludeThenExcludeMultipleScannersByIdOnHeaders)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    // First, include both by ID
    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"include": [{"id":"scanner-001"},{"id":"scanner-003"}], "exclude": [{"tags": {"category": "credential"}}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override1"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("api_key"), alloc),
            STRL("sk_live_1234567890abcdef"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto headers_schema = test::object_to_json(
            *ddwaf_object_find(attributes, STRL("server.request.headers.schema")));
        EXPECT_NE(headers_schema.find(R"("email":[8,{"type":"email","category":"pii"}])"),
            std::string::npos);
        EXPECT_NE(headers_schema.find(R"("api_key":[8,{"type":"api_key","category":"auth"}])"),
            std::string::npos);

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    // Then, exclude both by ID; excluded by ID wins, leaving none
    ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-headers"}], "scanners": {"exclude": [{"id":"scanner-001"},{"id":"scanner-003"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override2"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);

        auto *value = ddwaf_object_insert_key(&map, STRL("server.request.headers"), alloc);
        ddwaf_object_set_map(value, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("email"), alloc),
            STRL("employee@company.com"), alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("api_key"), alloc),
            STRL("sk_live_1234567890abcdef"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto headers_schema = test::object_to_json(
            *ddwaf_object_find(attributes, STRL("server.request.headers.schema")));
        EXPECT_NE(headers_schema.find(R"("email":[8])"), std::string::npos);
        EXPECT_NE(headers_schema.find(R"("api_key":[8])"), std::string::npos);
        EXPECT_EQ(headers_schema.find(R"({"type":"email","category":"pii"})"), std::string::npos);
        EXPECT_EQ(
            headers_schema.find(R"({"type":"api_key","category":"auth"})"), std::string::npos);

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestProcessorOverridesIntegration, IncludeMultipleByTagsExcludeOneById)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto *builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto processors = read_json_file("processors.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("processors"), &processors, nullptr);
    ddwaf_object_destroy(&processors, alloc);

    auto scanners = read_json_file("scanners.json", base_dir);
    ddwaf_builder_add_or_update_config(builder, LSTRARG("scanners"), &scanners, nullptr);
    ddwaf_object_destroy(&scanners, alloc);

    auto ovrd = json_to_object(
        R"({"processor_overrides": [{"target":[{"id":"extract-content"}], "scanners": {"include": [{"tags":{"type":"email"}},{"tags":{"type":"api_key"}}], "exclude": [{"id":"scanner-003"}]}}]})");
    ddwaf_builder_add_or_update_config(builder, LSTRARG("override"), &ovrd, nullptr);
    ddwaf_object_destroy(&ovrd, alloc);

    auto *handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);

    auto *value = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
    ddwaf_object_set_map(value, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(value, STRL("email"), alloc), STRL("employee@company.com"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(value, STRL("api_key"), alloc),
        STRL("sk_live_1234567890abcdef"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
    EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

    auto body_schema =
        test::object_to_json(*ddwaf_object_find(attributes, STRL("server.request.body.schema")));
    EXPECT_NE(
        body_schema.find(R"("email":[8,{"type":"email","category":"pii"}])"), std::string::npos);
    EXPECT_NE(body_schema.find(R"("api_key":[8])"), std::string::npos);
    EXPECT_EQ(body_schema.find(R"("type":"api_key","category":"auth")"), std::string::npos);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

} // namespace
