// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../test_utils.hpp"

#include "parameter.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/diagnostics/";

TEST(TestDiagnosticsIntegration, Rules)
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

        auto version = ddwaf::parser::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.2");

        auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 3);

        auto loaded = ddwaf::parser::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 4);
        EXPECT_NE(loaded.find("rule1"), loaded.end());
        EXPECT_NE(loaded.find("rule2"), loaded.end());
        EXPECT_NE(loaded.find("rule3"), loaded.end());
        EXPECT_NE(loaded.find("rule4"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsIntegration, RulesWithErrors)
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

        auto version = ddwaf::parser::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.1");

        auto rules = ddwaf::parser::at<parameter::map>(root_map, "rules");
        EXPECT_EQ(rules.size(), 3);

        auto loaded = ddwaf::parser::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("rule1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 5);
        EXPECT_NE(failed.find("rule1"), failed.end());
        EXPECT_NE(failed.find("index:2"), failed.end());
        EXPECT_NE(failed.find("rule4"), failed.end());
        EXPECT_NE(failed.find("rule5"), failed.end());
        EXPECT_NE(failed.find("rule6"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 4);

        {
            auto it = errors.find("duplicate rule");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_NE(error_rules.find("rule1"), error_rules.end());
        }

        {
            auto it = errors.find("missing key 'id'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_NE(error_rules.find("index:2"), error_rules.end());
        }

        {
            auto it = errors.find("missing key 'type'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 2);
            EXPECT_NE(error_rules.find("rule4"), error_rules.end());
            EXPECT_NE(error_rules.find("rule5"), error_rules.end());
        }

        {
            auto it = errors.find("missing key 'name'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_NE(error_rules.find("rule6"), error_rules.end());
        }

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsIntegration, CustomRules)
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

        auto version = ddwaf::parser::at<std::string>(root_map, "ruleset_version");
        EXPECT_STR(version, "5.4.3");

        auto rules = ddwaf::parser::at<parameter::map>(root_map, "custom_rules");
        EXPECT_EQ(rules.size(), 3);

        auto loaded = ddwaf::parser::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 4);
        EXPECT_NE(loaded.find("custom_rule1"), loaded.end());
        EXPECT_NE(loaded.find("custom_rule2"), loaded.end());
        EXPECT_NE(loaded.find("custom_rule3"), loaded.end());
        EXPECT_NE(loaded.find("custom_rule4"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsIntegration, Processor)
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

        auto processor = ddwaf::parser::at<parameter::map>(root_map, "processors");

        auto loaded = ddwaf::parser::at<parameter::string_set>(processor, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("processor-001"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(processor, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(processor, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

} // namespace
