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
        EXPECT_EQ(rules.size(), 4);

        auto loaded = ddwaf::parser::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 4);
        EXPECT_TRUE(loaded.contains("rule1"));
        EXPECT_TRUE(loaded.contains("rule2"));
        EXPECT_TRUE(loaded.contains("rule3"));
        EXPECT_TRUE(loaded.contains("rule4"));

        auto failed = ddwaf::parser::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::parser::at<parameter::map>(rules, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::parser::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 5);
        EXPECT_TRUE(required.contains("value1"));
        EXPECT_TRUE(required.contains("value2"));
        EXPECT_TRUE(required.contains("value3"));
        EXPECT_TRUE(required.contains("value4"));
        EXPECT_TRUE(required.contains("value34"));

        auto optional = ddwaf::parser::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 0);

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
        EXPECT_EQ(rules.size(), 4);

        auto loaded = ddwaf::parser::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rule1"));

        auto failed = ddwaf::parser::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 5);
        EXPECT_TRUE(failed.contains("rule1"));
        EXPECT_TRUE(failed.contains("index:2"));
        EXPECT_TRUE(failed.contains("rule4"));
        EXPECT_TRUE(failed.contains("rule5"));
        EXPECT_TRUE(failed.contains("rule6"));

        auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
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

        auto addresses = ddwaf::parser::at<parameter::map>(rules, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::parser::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 1);
        EXPECT_TRUE(required.contains("value1"));

        auto optional = ddwaf::parser::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 0);

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
        EXPECT_EQ(rules.size(), 4);

        auto loaded = ddwaf::parser::at<parameter::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 4);
        EXPECT_TRUE(loaded.contains("custom_rule1"));
        EXPECT_TRUE(loaded.contains("custom_rule2"));
        EXPECT_TRUE(loaded.contains("custom_rule3"));
        EXPECT_TRUE(loaded.contains("custom_rule4"));

        auto failed = ddwaf::parser::at<parameter::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::parser::at<parameter::map>(rules, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::parser::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 5);
        EXPECT_TRUE(required.contains("value1"));
        EXPECT_TRUE(required.contains("value2"));
        EXPECT_TRUE(required.contains("value3"));
        EXPECT_TRUE(required.contains("value4"));
        EXPECT_TRUE(required.contains("value34"));

        auto optional = ddwaf::parser::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 0);

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
        EXPECT_EQ(processor.size(), 4);

        auto loaded = ddwaf::parser::at<parameter::string_set>(processor, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("processor-001"));

        auto failed = ddwaf::parser::at<parameter::string_set>(processor, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(processor, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto addresses = ddwaf::parser::at<parameter::map>(processor, "addresses");
        EXPECT_EQ(addresses.size(), 2);

        auto required = ddwaf::parser::at<parameter::string_set>(addresses, "required");
        EXPECT_EQ(required.size(), 1);
        EXPECT_TRUE(required.contains("waf.context.processor"));

        auto optional = ddwaf::parser::at<parameter::string_set>(addresses, "optional");
        EXPECT_EQ(optional.size(), 1);
        EXPECT_TRUE(optional.contains("server.request.body"));

        ddwaf_object_free(&root);
    }

    ddwaf_destroy(handle);
}

} // namespace
