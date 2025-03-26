// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

#include "configuration/common/common.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "ddwaf.h"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/diagnostics/v2/";

TEST(TestDiagnosticsV2Integration, InvalidConfigType)
{
    auto rule = yaml_to_object<ddwaf_object>(
        R"([version, '2.1', [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]])");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto error = ddwaf::at<std::string>(root_map, "error");
    EXPECT_STR(error, "invalid configuration type, expected 'map', obtained 'array'");

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, UnsupportedSchema)
{
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '3.0', metadata: {rules_version: '1.2.7'}, rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto error = ddwaf::at<std::string>(root_map, "error");
    EXPECT_STR(error, "unsupported schema version: 3.x");

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, NoSchema)
{
    auto rule = yaml_to_object<ddwaf_object>(
        R"({ metadata: {rules_version: '1.2.7'}, rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
    EXPECT_STREQ(version.c_str(), "1.2.7");

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);
    EXPECT_NE(loaded.find("1"), loaded.end());

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 0);

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 0);

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, BasicRule)
{
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
    EXPECT_STREQ(version.c_str(), "1.2.7");

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);
    EXPECT_NE(loaded.find("1"), loaded.end());

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 0);

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 0);

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, BasicRuleWithUpdate)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_object_free(&rule);
    ddwaf_builder_destroy(builder);
}

TEST(TestDiagnosticsV2Integration, NullRuleset)
{
    ddwaf_object diagnostics;
    ddwaf_object_invalid(&diagnostics);
    ddwaf_handle handle = ddwaf_init(nullptr, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);

    EXPECT_EQ(diagnostics.type, DDWAF_OBJ_INVALID);
}

TEST(TestDiagnosticsV2Integration, InvalidRule)
{
    auto rule = read_file<ddwaf_object>("invalid_single.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);
    EXPECT_NE(failed.find("1"), failed.end());

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV2Integration, MultipleSameInvalidRules)
{
    auto rule = read_file<ddwaf_object>("invalid_multiple_same.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 2);
    EXPECT_NE(failed.find("1"), failed.end());
    EXPECT_NE(failed.find("2"), failed.end());

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 2);
    EXPECT_NE(error_rules.find("1"), error_rules.end());
    EXPECT_NE(error_rules.find("2"), error_rules.end());

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV2Integration, MultipleDiffInvalidRules)
{
    auto rule = read_file<ddwaf_object>("invalid_multiple_diff.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 2);
    EXPECT_NE(failed.find("1"), failed.end());
    EXPECT_NE(failed.find("2"), failed.end());

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());
    }

    auto warnings = ddwaf::at<raw_configuration::map>(rules, "warnings");
    EXPECT_EQ(warnings.size(), 1);
    {
        auto it = warnings.find("unknown operator: 'squash'");
        EXPECT_NE(it, warnings.end());

        auto warning_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(warning_rules.size(), 1);
        EXPECT_NE(warning_rules.find("2"), warning_rules.end());
    }

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV2Integration, MultipleMixInvalidRules)
{
    auto rule = read_file<ddwaf_object>("invalid_multiple_mix.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);
    EXPECT_NE(loaded.find("5"), loaded.end());

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 4);
    EXPECT_NE(failed.find("1"), failed.end());
    EXPECT_NE(failed.find("2"), failed.end());
    EXPECT_NE(failed.find("3"), failed.end());
    EXPECT_NE(failed.find("4"), failed.end());

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 2);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 2);
        EXPECT_NE(error_rules.find("1"), error_rules.end());
        EXPECT_NE(error_rules.find("3"), error_rules.end());
    }

    {
        auto it = errors.find("missing key 'inputs'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("4"), error_rules.end());
    }

    auto warnings = ddwaf::at<raw_configuration::map>(rules, "warnings");
    EXPECT_EQ(warnings.size(), 1);
    {
        auto it = warnings.find("unknown operator: 'squash'");
        EXPECT_NE(it, warnings.end());

        auto warning_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(warning_rules.size(), 1);
        EXPECT_NE(warning_rules.find("2"), warning_rules.end());
    }
    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, InvalidDuplicate)
{
    auto rule = read_file<ddwaf_object>("invalid_duplicate.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);
    EXPECT_NE(loaded.find("1"), loaded.end());

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);
    EXPECT_NE(failed.find("1"), failed.end());

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("duplicate rule");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, InvalidRuleset)
{
    auto rule = read_file<ddwaf_object>("invalid_ruleset.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::raw_configuration root(diagnostics);
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 400);

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 19);

    for (auto &[key, value] : errors) {
        auto rules = static_cast<ddwaf::raw_configuration::vector>(raw_configuration(value));
        EXPECT_EQ(rules.size(), 20);
    }

    auto warnings = ddwaf::at<raw_configuration::map>(rules, "warnings");
    EXPECT_EQ(warnings.size(), 1);

    for (auto &[key, value] : warnings) {
        auto rules = static_cast<ddwaf::raw_configuration::vector>(raw_configuration(value));
        EXPECT_EQ(rules.size(), 20);
    }

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV2Integration, MultipleRules)
{
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root = diagnostics;
        auto root_map = static_cast<raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.2");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 4);
        EXPECT_TRUE(loaded.contains("rule1"));
        EXPECT_TRUE(loaded.contains("rule2"));
        EXPECT_TRUE(loaded.contains("rule3"));
        EXPECT_TRUE(loaded.contains("rule4"));

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<raw_configuration::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RulesWithMinVersion)
{
    auto rule = read_file<ddwaf_object>("rules_min_version.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root = diagnostics;
        auto root_map = static_cast<raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.2");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rule1"));

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<raw_configuration::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_TRUE(skipped.contains("rule2"));

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RulesWithMaxVersion)
{
    auto rule = read_file<ddwaf_object>("rules_max_version.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root = diagnostics;
        auto root_map = static_cast<raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.2");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rule1"));

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<raw_configuration::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_TRUE(skipped.contains("rule2"));

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RulesWithMinMaxVersion)
{
    auto rule = read_file<ddwaf_object>("rules_min_max_version.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root = diagnostics;
        auto root_map = static_cast<raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.2");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rule1"));

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<raw_configuration::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 2);
        EXPECT_TRUE(skipped.contains("rule2"));
        EXPECT_TRUE(skipped.contains("rule3"));

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RulesWithErrors)
{
    auto rule = read_file<ddwaf_object>("rules_with_errors.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root = diagnostics;
        auto root_map = static_cast<raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.1");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rule1"));

        auto skipped = ddwaf::at<raw_configuration::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 5);
        EXPECT_TRUE(failed.contains("rule1"));
        EXPECT_TRUE(failed.contains("index:2"));
        EXPECT_TRUE(failed.contains("rule4"));
        EXPECT_TRUE(failed.contains("rule5"));
        EXPECT_TRUE(failed.contains("rule6"));

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 4);

        {
            auto it = errors.find("duplicate rule");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_TRUE(error_rules.contains("rule1"));
        }

        {
            auto it = errors.find("missing key 'id'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_TRUE(error_rules.contains("index:2"));
        }

        {
            auto it = errors.find("missing key 'type'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 2);
            EXPECT_TRUE(error_rules.contains("rule4"));
            EXPECT_TRUE(error_rules.contains("rule5"));
        }

        {
            auto it = errors.find("missing key 'name'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_TRUE(error_rules.contains("rule6"));
        }

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, CustomRules)
{
    auto rule = read_file<ddwaf_object>("custom_rules.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root = diagnostics;
        auto root_map = static_cast<raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.3");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "custom_rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 4);
        EXPECT_TRUE(loaded.contains("custom_rule1"));
        EXPECT_TRUE(loaded.contains("custom_rule2"));
        EXPECT_TRUE(loaded.contains("custom_rule3"));
        EXPECT_TRUE(loaded.contains("custom_rule4"));

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<raw_configuration::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, InputFilter)
{
    auto rule = read_file<ddwaf_object>("input_filter.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root = diagnostics;
        auto root_map = static_cast<raw_configuration::map>(root);

        auto exclusions = ddwaf::at<raw_configuration::map>(root_map, "exclusions");
        EXPECT_EQ(exclusions.size(), 5);

        auto loaded = ddwaf::at<raw_configuration::string_set>(exclusions, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("1"));

        auto failed = ddwaf::at<raw_configuration::string_set>(exclusions, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<raw_configuration::string_set>(exclusions, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<raw_configuration::map>(exclusions, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RuleData)
{
    auto rule = read_file<ddwaf_object>("rule_data.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root = diagnostics;
        auto root_map = static_cast<raw_configuration::map>(root);

        auto rule_data = ddwaf::at<raw_configuration::map>(root_map, "rules_data");
        EXPECT_EQ(rule_data.size(), 5);

        auto loaded = ddwaf::at<raw_configuration::string_set>(rule_data, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_TRUE(loaded.contains("ip_data"));
        EXPECT_TRUE(loaded.contains("usr_data"));

        auto failed = ddwaf::at<raw_configuration::string_set>(rule_data, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<raw_configuration::string_set>(rule_data, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<raw_configuration::map>(rule_data, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, Processor)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root = diagnostics;
        auto root_map = static_cast<raw_configuration::map>(root);

        auto processor = ddwaf::at<raw_configuration::map>(root_map, "processors");
        EXPECT_EQ(processor.size(), 5);

        auto loaded = ddwaf::at<raw_configuration::string_set>(processor, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("processor-001"));

        auto failed = ddwaf::at<raw_configuration::string_set>(processor, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<raw_configuration::string_set>(processor, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<raw_configuration::map>(processor, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, InvalidRulesContainer)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestDiagnosticsV2Integration, InvalidCustomRulesContainer)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, custom_rules: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "custom_rules");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestDiagnosticsV2Integration, InvalidExclusionsContainer)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, exclusions: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "exclusions");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestDiagnosticsV2Integration, InvalidOverridesContainer)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules_override: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules_override");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestDiagnosticsV2Integration, InvalidScannersContainer)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, scanners: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "scanners");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestDiagnosticsV2Integration, InvalidProcessorsContainer)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, processors: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "processors");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestDiagnosticsV2Integration, InvalidActionsContainer)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, actions: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "actions");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestDiagnosticsV2Integration, InvalidRuleDataContainer)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules_data: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules_data");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_destroy(builder);
}

TEST(TestDiagnosticsV2Integration, InvalidExclusionDataContainer)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, exclusion_data: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, &diagnostics);
    ddwaf_object_free(&rule);

    {
        ddwaf::raw_configuration root(diagnostics);
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "exclusion_data");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_builder_destroy(builder);
}

} // namespace
