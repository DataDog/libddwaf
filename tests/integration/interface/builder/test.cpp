// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstring>
#include <initializer_list>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/raw_configuration.hpp"
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

// Helpers for the tests on empty data lists

struct config_result {
    bool accepted{false};
    std::set<std::string> loaded;
    std::set<std::string> failed;
};

// Collects the ids reported as loaded and failed for one section of the diagnostics
config_result collect_diagnostics(
    bool accepted, ddwaf_object &diagnostics, std::string_view section)
{
    auto *alloc = ddwaf_get_default_allocator();
    config_result result{.accepted = accepted, .loaded = {}, .failed = {}};

    ddwaf::raw_configuration root(reinterpret_cast<const ddwaf::detail::object &>(diagnostics));
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);
    auto it = root_map.find(section);
    if (it != root_map.end()) {
        auto section_map = static_cast<ddwaf::raw_configuration::map>(it->second);
        for (auto id : ddwaf::at<ddwaf::raw_configuration::string_set>(section_map, "loaded")) {
            result.loaded.emplace(id);
        }
        for (auto id : ddwaf::at<ddwaf::raw_configuration::string_set>(section_map, "failed")) {
            result.failed.emplace(id);
        }
    }

    ddwaf_object_destroy(&diagnostics, alloc);
    return result;
}

config_result add_yaml_config(
    ddwaf_builder builder, std::string_view path, const char *yaml, std::string_view section)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto config = yaml_to_object<ddwaf_object>(yaml);
    EXPECT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    bool accepted = ddwaf_builder_add_or_update_config(
        builder, path.data(), path.size(), &config, &diagnostics);
    ddwaf_object_destroy(&config, alloc);

    return collect_diagnostics(accepted, diagnostics, section);
}

config_result add_json_config(
    ddwaf_builder builder, std::string_view path, const char *json, std::string_view section)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object config;
    EXPECT_TRUE(ddwaf_object_from_json(&config, json, strlen(json), alloc));

    ddwaf_object diagnostics;
    bool accepted = ddwaf_builder_add_or_update_config(
        builder, path.data(), path.size(), &config, &diagnostics);
    ddwaf_object_destroy(&config, alloc);

    return collect_diagnostics(accepted, diagnostics, section);
}

// Evaluates a new context with the provided inputs and returns the result
// code. The ids of the rules in the events are stored in rule_ids.
DDWAF_RET_CODE eval_inputs(ddwaf_handle handle,
    std::initializer_list<std::pair<std::string_view, std::string_view>> inputs,
    std::vector<std::string> &rule_ids)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    EXPECT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, inputs.size(), alloc);
    for (const auto &[address, value] : inputs) {
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, address.data(), address.size(), alloc), value.data(),
            value.size(), alloc);
    }

    ddwaf_object out;
    auto code = ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME);

    rule_ids.clear();
    auto events = to_view(out).find("events");
    if (events.has_value()) {
        auto data = ddwaf::test::object_to_json(events.ref());
        YAML::Node doc = YAML::Load(data.c_str());
        for (const auto &event : doc) {
            rule_ids.emplace_back(event["rule"]["id"].as<std::string>());
        }
    }

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    return code;
}

constexpr const char *ip_rule_with_data = R"(
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
)";

constexpr const char *empty_ip_rules_data = R"(
version: '2.1'
rules_data:
  - {id: blocked_ips, type: ip_with_expiration, data: []}
)";

constexpr const char *ip_rules_data = R"(
version: '2.1'
rules_data:
  - id: blocked_ips
    type: ip_with_expiration
    data:
      - {value: 1.2.3.4, expiration: 0}
)";

// Table variant 1: empty data, with a rule that uses it
TEST(TestEngineBuilderFunctional, EmptyIpDataWithRule)
{
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto result = add_yaml_config(builder, "rules", R"(
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
)",
        "rules_data");
    EXPECT_TRUE(result.accepted);
    EXPECT_EQ(result.loaded, std::set<std::string>{"blocked_ips"});
    EXPECT_TRUE(result.failed.empty());

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    std::vector<std::string> ids;
    EXPECT_EQ(eval_inputs(handle, {{"http.client_ip", "1.2.3.4"}}, ids), DDWAF_OK);
    EXPECT_TRUE(ids.empty());

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

// Table variant 2: empty data, no rule that uses it
TEST(TestEngineBuilderFunctional, EmptyDataWithoutRule)
{
    // (a) The exact configuration of the issue. There are no rules, so there
    // is no handle, but the build must not crash.
    {
        ddwaf_builder builder = ddwaf_builder_init();
        ASSERT_NE(builder, nullptr);

        auto result = add_yaml_config(builder, "rules_data", empty_ip_rules_data, "rules_data");
        EXPECT_TRUE(result.accepted);
        EXPECT_EQ(result.loaded, std::set<std::string>{"blocked_ips"});
        EXPECT_TRUE(result.failed.empty());

        ddwaf_handle handle = ddwaf_builder_build_instance(builder);
        EXPECT_EQ(handle, nullptr);

        ddwaf_builder_destroy(builder);
    }

    // (b) A rule which doesn't use the data, and the empty data in another config
    {
        ddwaf_builder builder = ddwaf_builder_init();
        ASSERT_NE(builder, nullptr);

        auto rules = add_yaml_config(builder, "rules", R"(
version: '2.1'
rules:
  - id: 1
    name: rule1
    tags: {type: type1, category: category}
    conditions:
      - operator: exact_match
        parameters:
          inputs: [{address: usr.id}]
          list: [admin]
)",
            "rules");
        EXPECT_TRUE(rules.accepted);

        auto data = add_yaml_config(builder, "rules_data", empty_ip_rules_data, "rules_data");
        EXPECT_TRUE(data.accepted);
        EXPECT_EQ(data.loaded, std::set<std::string>{"blocked_ips"});

        ddwaf_handle handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        std::vector<std::string> ids;
        EXPECT_EQ(eval_inputs(handle, {{"usr.id", "admin"}}, ids), DDWAF_MATCH);
        EXPECT_EQ(ids, std::vector<std::string>{"1"});

        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }
}

// Table variant 3: type data_with_expiration, empty data
TEST(TestEngineBuilderFunctional, EmptyDataWithExpirationType)
{
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto result = add_yaml_config(builder, "rules", R"(
version: '2.1'
rules:
  - id: 1
    name: rule1
    tags: {type: type1, category: category}
    conditions:
      - operator: exact_match
        parameters:
          inputs: [{address: usr.id}]
          data: usr_data
rules_data:
  - {id: usr_data, type: data_with_expiration, data: []}
)",
        "rules_data");
    EXPECT_TRUE(result.accepted);
    EXPECT_EQ(result.loaded, std::set<std::string>{"usr_data"});
    EXPECT_TRUE(result.failed.empty());

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    std::vector<std::string> ids;
    EXPECT_EQ(eval_inputs(handle, {{"usr.id", "paco"}}, ids), DDWAF_OK);
    EXPECT_TRUE(ids.empty());

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

// Table variant 4: rule in one config, empty data in another one
TEST(TestEngineBuilderFunctional, EmptyDataInSeparateConfig)
{
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    EXPECT_TRUE(add_yaml_config(builder, "rules", ip_rule_with_data, "rules_data").accepted);

    {
        auto result = add_yaml_config(builder, "empty", empty_ip_rules_data, "rules_data");
        EXPECT_TRUE(result.accepted);
        EXPECT_EQ(result.loaded, std::set<std::string>{"blocked_ips"});
        EXPECT_TRUE(result.failed.empty());
    }

    std::vector<std::string> ids;

    {
        ddwaf_handle handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);
        EXPECT_EQ(eval_inputs(handle, {{"http.client_ip", "1.2.3.4"}}, ids), DDWAF_OK);
        ddwaf_destroy(handle);
    }

    // Empty and non-empty data for the same data id
    EXPECT_TRUE(add_yaml_config(builder, "filled", ip_rules_data, "rules_data").accepted);

    {
        ddwaf_handle handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);
        EXPECT_EQ(eval_inputs(handle, {{"http.client_ip", "1.2.3.4"}}, ids), DDWAF_MATCH);
        EXPECT_EQ(ids, std::vector<std::string>{"1"});
        ddwaf_destroy(handle);
    }

    // The last IP is removed
    EXPECT_TRUE(add_yaml_config(builder, "filled", empty_ip_rules_data, "rules_data").accepted);

    {
        ddwaf_handle handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);
        EXPECT_EQ(eval_inputs(handle, {{"http.client_ip", "1.2.3.4"}}, ids), DDWAF_OK);
        EXPECT_TRUE(ids.empty());
        ddwaf_destroy(handle);
    }

    // The first empty config is removed
    EXPECT_TRUE(ddwaf_builder_remove_config(builder, LSTRARG("empty")));

    {
        ddwaf_handle handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);
        EXPECT_EQ(eval_inputs(handle, {{"http.client_ip", "1.2.3.4"}}, ids), DDWAF_OK);
        ddwaf_destroy(handle);
    }

    ddwaf_builder_destroy(builder);
}

// Table variant 5: the same configuration built by the JSON parser
TEST(TestEngineBuilderFunctional, EmptyDataFromJson)
{
    // (a) The exact JSON of the issue
    {
        ddwaf_builder builder = ddwaf_builder_init();
        ASSERT_NE(builder, nullptr);

        auto result = add_json_config(builder, "/c",
            R"({"version": "2.1", "rules_data": [{"id": "blocked_ips", "type": "ip_with_expiration", "data": []}]})",
            "rules_data");
        EXPECT_TRUE(result.accepted);
        EXPECT_EQ(result.loaded, std::set<std::string>{"blocked_ips"});
        EXPECT_TRUE(result.failed.empty());

        ddwaf_handle handle = ddwaf_builder_build_instance(builder);
        EXPECT_EQ(handle, nullptr);

        ddwaf_builder_destroy(builder);
    }

    // (b) The same JSON, with a rule which uses the data
    {
        ddwaf_builder builder = ddwaf_builder_init();
        ASSERT_NE(builder, nullptr);

        auto result = add_json_config(builder, "/c",
            R"({"version": "2.1",
                "rules": [{"id": "1", "name": "rule1", "tags": {"type": "type1", "category": "category"},
                           "conditions": [{"operator": "ip_match",
                                           "parameters": {"inputs": [{"address": "http.client_ip"}],
                                                          "data": "blocked_ips"}}]}],
                "rules_data": [{"id": "blocked_ips", "type": "ip_with_expiration", "data": []}]})",
            "rules_data");
        EXPECT_TRUE(result.accepted);
        EXPECT_EQ(result.loaded, std::set<std::string>{"blocked_ips"});

        ddwaf_handle handle = ddwaf_builder_build_instance(builder);
        ASSERT_NE(handle, nullptr);

        std::vector<std::string> ids;
        EXPECT_EQ(eval_inputs(handle, {{"http.client_ip", "1.2.3.4"}}, ids), DDWAF_OK);
        EXPECT_TRUE(ids.empty());

        ddwaf_destroy(handle);
        ddwaf_builder_destroy(builder);
    }
}

// Negated conditions keep their NOT semantics: an empty data set contains no
// value, so the negated condition is true when the input is present.
TEST(TestEngineBuilderFunctional, EmptyIpDataNegatedRule)
{
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto result = add_yaml_config(builder, "rules", R"(
version: '2.1'
rules:
  - id: 1
    name: rule1
    tags: {type: type1, category: category}
    conditions:
      - operator: '!ip_match'
        parameters:
          inputs: [{address: http.client_ip}]
          data: allowed_ips
rules_data:
  - {id: allowed_ips, type: ip_with_expiration, data: []}
)",
        "rules_data");
    EXPECT_TRUE(result.accepted);
    EXPECT_EQ(result.loaded, std::set<std::string>{"allowed_ips"});

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    std::vector<std::string> ids;
    EXPECT_EQ(eval_inputs(handle, {{"http.client_ip", "1.2.3.4"}, {"usr.id", "admin"}}, ids),
        DDWAF_MATCH);
    EXPECT_EQ(ids, std::vector<std::string>{"1"});

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestEngineBuilderFunctional, EmptyStringDataNegatedRule)
{
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto result = add_yaml_config(builder, "rules", R"(
version: '2.1'
rules:
  - id: 1
    name: rule1
    tags: {type: type1, category: category}
    conditions:
      - operator: '!exact_match'
        parameters:
          inputs: [{address: usr.id}]
          data: allowed_users
rules_data:
  - {id: allowed_users, type: data_with_expiration, data: []}
)",
        "rules_data");
    EXPECT_TRUE(result.accepted);
    EXPECT_EQ(result.loaded, std::set<std::string>{"allowed_users"});

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    std::vector<std::string> ids;
    EXPECT_EQ(eval_inputs(handle, {{"http.client_ip", "1.2.3.4"}, {"usr.id", "admin"}}, ids),
        DDWAF_MATCH);
    EXPECT_EQ(ids, std::vector<std::string>{"1"});

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

// Control: with a data id which was never loaded, there is no matcher, and
// the negated condition is false.
TEST(TestEngineBuilderFunctional, UnknownDataIdNegatedRule)
{
    ddwaf_builder builder = ddwaf_builder_init();
    ASSERT_NE(builder, nullptr);

    auto result = add_yaml_config(builder, "rules", R"(
version: '2.1'
rules:
  - id: 1
    name: rule1
    tags: {type: type1, category: category}
    conditions:
      - operator: '!ip_match'
        parameters:
          inputs: [{address: http.client_ip}]
          data: missing_id
)",
        "rules");
    EXPECT_TRUE(result.accepted);

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle, nullptr);

    std::vector<std::string> ids;
    EXPECT_EQ(
        eval_inputs(handle, {{"http.client_ip", "1.2.3.4"}, {"usr.id", "admin"}}, ids), DDWAF_OK);
    EXPECT_TRUE(ids.empty());

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

} // namespace
