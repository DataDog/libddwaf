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

TEST(TestEngineBuilderFunctional, EmptyConfig)
{
    auto config = yaml_to_object("{}");
    ASSERT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_builder builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &config, nullptr);
    ddwaf_object_free(&config);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, BaseRules)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    // Add the first config
    {
        auto config = read_file("base_rules_1.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr);
        ddwaf_object_free(&config);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the rules work
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    // Update the config
    {
        ddwaf_destroy(handle);
        auto config = read_file("base_rules_2.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr);
        ddwaf_object_free(&config);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the old rules don't work and new ones do
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value2", ddwaf_object_string(&tmp, "rule2"));
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    // Remove the rules
    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("rules"));
    handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, CustomRules)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);
    ASSERT_NE(builder, nullptr);

    // Add the first config
    {
        auto config = read_file("custom_rules_1.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr);
        ddwaf_object_free(&config);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the rules work
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    // Update the config
    {
        ddwaf_destroy(handle);
        auto config = read_file("custom_rules_2.yaml", base_dir);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &config, nullptr);
        ddwaf_object_free(&config);
    }

    handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    // Test that the old rules don't work and new ones do
    {
        ddwaf_context context = ddwaf_context_init(handle);

        ddwaf_object tmp;
        ddwaf_object root;

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value2", ddwaf_object_string(&tmp, "rule2"));
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    // Remove the rules
    ddwaf_destroy(handle);
    ddwaf_builder_remove_config(builder, LSTRARG("rules"));
    handle = ddwaf_builder_build_instance(builder);
    ASSERT_EQ(handle, nullptr);

    ddwaf_builder_destroy(builder);
}

} // namespace
