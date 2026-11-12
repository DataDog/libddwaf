// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"
#include "version.hpp"

using namespace ddwaf;

namespace {

constexpr std::string_view base_dir = "integration/interface/builder/";

TEST(TestEngineBuilderFunctional, InvalidConfigType)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config = yaml_to_object<ddwaf_object>("[]");
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_FALSE(ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, InvalidSectionType)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config = yaml_to_object<ddwaf_object>("{rules: {}}");
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_FALSE(ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, EmptyConfig)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config = yaml_to_object<ddwaf_object>("{}");
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, ConfigWithAllSkippedItems)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config = read_file<ddwaf_object>("all_skipped_items.yaml", base_dir);
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, ConfigWithNoItemsButMultipleSections)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config = read_file<ddwaf_object>("multiple_sections_empty_config.yaml", base_dir);
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, AllLoadableItemsFailedSingleSection)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config =
        read_file<ddwaf_object>("multiple_sections_one_with_invalid_items.yaml", base_dir);
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_FALSE(ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, AllLoadableItemsFailedMultipleSection)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config = read_file<ddwaf_object>("multiple_empty_sections_invalid_items.yaml", base_dir);
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_FALSE(ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, OneLoadedItemEverythingElseFailed)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config =
        read_file<ddwaf_object>("multiple_empty_sections_invalid_and_valid_items.yaml", base_dir);
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, InvalidSectionAndLoadableItems)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config = read_file<ddwaf_object>("invalid_section_and_loadable_items.yaml", base_dir);
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, BaseRules)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    // Add the first config
    {
        auto config = read_file<ddwaf_object>("base_rules_1.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_TRUE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the rules work
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value1"), alloc), STRL("rule1"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    // Update the config
    {
        ddwaf_destroy(handle);
        auto config = read_file<ddwaf_object>("base_rules_2.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_TRUE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the old rules don't work and new ones do
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value1"), alloc), STRL("rule1"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value2"), alloc), STRL("rule2"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    // Remove the rules
    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("rules"));
    handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, RemoveDuplicateBaseRules)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    // Add the first config
    {
        auto config = read_file<ddwaf_object>("base_rules_1.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_TRUE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules1"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    // Add the second config with duplicate rule 1
    {
        auto config = read_file<ddwaf_object>("base_rules_1_2_duplicate.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_TRUE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules2"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that both rules work
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value1"), alloc), STRL("rule1"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value2"), alloc), STRL("rule2"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    // Remove the second rule2
    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("rules2"));
    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that only the remaining rule works
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value1"), alloc), STRL("rule1"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value2"), alloc), STRL("rule2"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("rules1"));
    handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);
    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, CustomRules)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    // Add the first config
    {
        auto config = read_file<ddwaf_object>("custom_rules_1.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_TRUE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the rules work
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value1"), alloc), STRL("rule1"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    // Update the config
    {
        ddwaf_destroy(handle);
        auto config = read_file<ddwaf_object>("custom_rules_2.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_TRUE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr));

        ddwaf_object_destroy(&config, alloc);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the old rules don't work and new ones do
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value1"), alloc), STRL("rule1"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value2"), alloc), STRL("rule2"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    // Remove the rules
    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("rules"));
    handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, InvalidSchemaVersionFormat)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config = yaml_to_object<ddwaf_object>("{version: abc}");
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_FALSE(ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    EXPECT_EQ(ddwaf_builder_get_config_paths(builder, nullptr, nullptr, 0), 0);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, RemoveRejectedConfig)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    // Add the first config
    {
        auto config = read_file<ddwaf_object>("base_rules_1.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_TRUE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules1"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    // Update the first config with an unsupported schema version
    {
        auto config = yaml_to_object<ddwaf_object>("{version: '3.0'}");
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_FALSE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules1"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    EXPECT_EQ(ddwaf_builder_get_config_paths(builder, nullptr, nullptr, 0), 0);

    // Provide the same rules through a second config
    {
        auto config = read_file<ddwaf_object>("base_rules_1.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_TRUE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules2"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    // The rejected config is no longer registered
    EXPECT_FALSE(ddwaf_builder_remove_config(builder, LSTRARG("rules1")));

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the rules from the second config work
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value1"), alloc), STRL("rule1"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, RejectedConfigWithLoadedItems)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    // Add the first config
    {
        auto config = read_file<ddwaf_object>("base_rules_1.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_TRUE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    // The second exclusion is invalid, so the config is rejected after loading the first one
    {
        auto config = yaml_to_object<ddwaf_object>(
            "{exclusions: [{id: 1, rules_target: [{rule_id: 1}]}, invalid]}");
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ASSERT_FALSE(
            ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusions"), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the exclusion from the rejected config is not applied
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("value1"), alloc), STRL("rule1"), alloc);
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, EmptyIpDataWithRule)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto config = yaml_to_object<ddwaf_object>(R"(
version: '2.1'
rules:
  - id: 1
    name: rule1
    tags: {type: type1, category: category}
    conditions:
      - operator: ip_match
        parameters:
          inputs: [{address: http.client_ip}]
          data: blocked_ips
rules_data:
  - {id: blocked_ips, type: ip_with_expiration, data: []}
)");
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    ASSERT_TRUE(ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr));
    ddwaf_object_destroy(&config, alloc);

    // An empty data list used to crash the build
    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("1.2.3.4"), alloc);
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_OK);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

} // namespace
