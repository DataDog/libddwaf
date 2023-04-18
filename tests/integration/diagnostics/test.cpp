// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../test.h"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/diagnostics/";
} // namespace

TEST(TestDiagnosticsIntegration, Rules)
{
    auto rule = readFile("rules.yaml", base_dir);
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

TEST(TestDiagnosticsIntegration, CustomRules)
{
    auto rule = readFile("custom_rules.yaml", base_dir);
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
