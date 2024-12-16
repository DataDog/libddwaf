// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

#include "configuration/common/common.hpp"
#include "parameter.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/diagnostics/v2/";

TEST(TestDiagnosticsV2Integration, BasicRule)
{
    auto rule = yaml_to_object(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
    EXPECT_STREQ(version.c_str(), "1.2.7");

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);
    EXPECT_NE(loaded.find("1"), loaded.end());

    auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 0);

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 0);

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, BasicRuleWithUpdate)
{
    auto rule = yaml_to_object(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);

    {

        ddwaf::parameter root(diagnostics);
        auto root_map = static_cast<ddwaf::parameter::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<parameter::map>(root_map, "rules");

        auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_handle new_handle = ddwaf_update(handle, &rule, &diagnostics);
    ASSERT_NE(handle, nullptr);

    {
        ddwaf::parameter root(diagnostics);
        auto root_map = static_cast<ddwaf::parameter::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<parameter::map>(root_map, "rules");

        auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&diagnostics);
    }

    ddwaf_object_free(&rule);

    ddwaf_destroy(handle);
    ddwaf_destroy(new_handle);
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
    auto rule = read_file("invalid_single.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);
    EXPECT_NE(failed.find("1"), failed.end());

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV2Integration, MultipleSameInvalidRules)
{
    auto rule = read_file("invalid_multiple_same.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 2);
    EXPECT_NE(failed.find("1"), failed.end());
    EXPECT_NE(failed.find("2"), failed.end());

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 2);
    EXPECT_NE(error_rules.find("1"), error_rules.end());
    EXPECT_NE(error_rules.find("2"), error_rules.end());

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV2Integration, MultipleDiffInvalidRules)
{
    auto rule = read_file("invalid_multiple_diff.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 2);
    EXPECT_NE(failed.find("1"), failed.end());
    EXPECT_NE(failed.find("2"), failed.end());

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 2);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());
    }

    {
        auto it = errors.find("unknown matcher: squash");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("2"), error_rules.end());
    }

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV2Integration, MultipleMixInvalidRules)
{
    auto rule = read_file("invalid_multiple_mix.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);
    EXPECT_NE(loaded.find("5"), loaded.end());

    auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 4);
    EXPECT_NE(failed.find("1"), failed.end());
    EXPECT_NE(failed.find("2"), failed.end());
    EXPECT_NE(failed.find("3"), failed.end());
    EXPECT_NE(failed.find("4"), failed.end());

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 3);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 2);
        EXPECT_NE(error_rules.find("1"), error_rules.end());
        EXPECT_NE(error_rules.find("3"), error_rules.end());
    }

    {
        auto it = errors.find("unknown matcher: squash");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("2"), error_rules.end());
    }

    {
        auto it = errors.find("missing key 'inputs'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("4"), error_rules.end());
    }

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, InvalidDuplicate)
{
    auto rule = read_file("invalid_duplicate.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);
    EXPECT_NE(loaded.find("1"), loaded.end());

    auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);
    EXPECT_NE(failed.find("1"), failed.end());

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("duplicate rule");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_free(&diagnostics);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, InvalidRuleset)
{
    auto rule = read_file("invalid_ruleset.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 400);

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 20);

    for (auto &[key, value] : errors) {
        auto rules = static_cast<ddwaf::parameter::vector>(parameter(value));
        EXPECT_EQ(rules.size(), 20);
    }

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV2Integration, MultipleRules)
{
    auto rule = read_file("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::parameter root = diagnostics;
        auto root_map = static_cast<parameter::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.2");

        auto rules = ddwaf::at<parameter::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 4);
        EXPECT_TRUE(loaded.contains("rule1"));
        EXPECT_TRUE(loaded.contains("rule2"));
        EXPECT_TRUE(loaded.contains("rule3"));
        EXPECT_TRUE(loaded.contains("rule4"));

        auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<parameter::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::at<parameter::map>(rules, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 5);
        EXPECT_TRUE(required.contains("value1"));
        EXPECT_TRUE(required.contains("value2"));
        EXPECT_TRUE(required.contains("value3"));
        EXPECT_TRUE(required.contains("value4"));
        EXPECT_TRUE(required.contains("value34"));

        auto optional = ddwaf::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RulesWithMinVersion)
{
    auto rule = read_file("rules_min_version.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::parameter root = diagnostics;
        auto root_map = static_cast<parameter::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.2");

        auto rules = ddwaf::at<parameter::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rule1"));

        auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<parameter::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_TRUE(skipped.contains("rule2"));

        auto errors = ddwaf::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::at<parameter::map>(rules, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 1);
        EXPECT_TRUE(required.contains("value1"));

        auto optional = ddwaf::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RulesWithMaxVersion)
{
    auto rule = read_file("rules_max_version.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::parameter root = diagnostics;
        auto root_map = static_cast<parameter::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.2");

        auto rules = ddwaf::at<parameter::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rule1"));

        auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<parameter::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_TRUE(skipped.contains("rule2"));

        auto errors = ddwaf::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::at<parameter::map>(rules, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 1);
        EXPECT_TRUE(required.contains("value1"));

        auto optional = ddwaf::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RulesWithMinMaxVersion)
{
    auto rule = read_file("rules_min_max_version.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::parameter root = diagnostics;
        auto root_map = static_cast<parameter::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.2");

        auto rules = ddwaf::at<parameter::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rule1"));

        auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<parameter::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 2);
        EXPECT_TRUE(skipped.contains("rule2"));
        EXPECT_TRUE(skipped.contains("rule3"));

        auto errors = ddwaf::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::at<parameter::map>(rules, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 1);
        EXPECT_TRUE(required.contains("value1"));

        auto optional = ddwaf::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RulesWithErrors)
{
    auto rule = read_file("rules_with_errors.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::parameter root = diagnostics;
        auto root_map = static_cast<parameter::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.1");

        auto rules = ddwaf::at<parameter::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rule1"));

        auto skipped = ddwaf::at<parameter::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 5);
        EXPECT_TRUE(failed.contains("rule1"));
        EXPECT_TRUE(failed.contains("index:2"));
        EXPECT_TRUE(failed.contains("rule4"));
        EXPECT_TRUE(failed.contains("rule5"));
        EXPECT_TRUE(failed.contains("rule6"));

        auto errors = ddwaf::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 4);

        {
            auto it = errors.find("duplicate rule");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_TRUE(error_rules.contains("rule1"));
        }

        {
            auto it = errors.find("missing key 'id'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_TRUE(error_rules.contains("index:2"));
        }

        {
            auto it = errors.find("missing key 'type'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 2);
            EXPECT_TRUE(error_rules.contains("rule4"));
            EXPECT_TRUE(error_rules.contains("rule5"));
        }

        {
            auto it = errors.find("missing key 'name'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_TRUE(error_rules.contains("rule6"));
        }

        auto addresses = ddwaf::at<parameter::map>(rules, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 1);
        EXPECT_TRUE(required.contains("value1"));

        auto optional = ddwaf::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, CustomRules)
{
    auto rule = read_file("custom_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::parameter root = diagnostics;
        auto root_map = static_cast<parameter::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.3");

        auto rules = ddwaf::at<parameter::map>(root_map, "custom_rules");
        EXPECT_EQ(rules.size(), 5);

        auto loaded = ddwaf::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 4);
        EXPECT_TRUE(loaded.contains("custom_rule1"));
        EXPECT_TRUE(loaded.contains("custom_rule2"));
        EXPECT_TRUE(loaded.contains("custom_rule3"));
        EXPECT_TRUE(loaded.contains("custom_rule4"));

        auto failed = ddwaf::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<parameter::string_set>(rules, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::at<parameter::map>(rules, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 5);
        EXPECT_TRUE(required.contains("value1"));
        EXPECT_TRUE(required.contains("value2"));
        EXPECT_TRUE(required.contains("value3"));
        EXPECT_TRUE(required.contains("value4"));
        EXPECT_TRUE(required.contains("value34"));

        auto optional = ddwaf::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, InputFilter)
{
    auto rule = read_file("input_filter.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::parameter root = diagnostics;
        auto root_map = static_cast<parameter::map>(root);

        auto exclusions = ddwaf::at<parameter::map>(root_map, "exclusions");
        EXPECT_EQ(exclusions.size(), 5);

        auto loaded = ddwaf::at<parameter::string_set>(exclusions, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("1"));

        auto failed = ddwaf::at<parameter::string_set>(exclusions, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<parameter::string_set>(exclusions, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<parameter::map>(exclusions, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::at<parameter::map>(exclusions, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 1);
        EXPECT_TRUE(required.contains("exclusion-filter-1-input"));

        auto optional = ddwaf::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 2);
        EXPECT_TRUE(optional.contains("rule1-input1"));
        EXPECT_TRUE(optional.contains("rule1-input2"));

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, RuleData)
{
    auto rule = read_file("rule_data.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::parameter root = diagnostics;
        auto root_map = static_cast<parameter::map>(root);

        auto rule_data = ddwaf::at<parameter::map>(root_map, "rules_data");
        EXPECT_EQ(rule_data.size(), 4);

        auto loaded = ddwaf::at<parameter::string_set>(rule_data, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_TRUE(loaded.contains("ip_data"));
        EXPECT_TRUE(loaded.contains("usr_data"));

        auto failed = ddwaf::at<parameter::string_set>(rule_data, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<parameter::string_set>(rule_data, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<parameter::map>(rule_data, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV2Integration, Processor)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, &config, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf::parameter root = diagnostics;
        auto root_map = static_cast<parameter::map>(root);

        auto processor = ddwaf::at<parameter::map>(root_map, "processors");
        EXPECT_EQ(processor.size(), 5);

        auto loaded = ddwaf::at<parameter::string_set>(processor, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("processor-001"));

        auto failed = ddwaf::at<parameter::string_set>(processor, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = ddwaf::at<parameter::string_set>(processor, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = ddwaf::at<parameter::map>(processor, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::at<parameter::map>(processor, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 1);
        EXPECT_TRUE(required.contains("waf.context.processor"));

        auto optional = ddwaf::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 1);
        EXPECT_TRUE(optional.contains("server.request.body"));

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

} // namespace
