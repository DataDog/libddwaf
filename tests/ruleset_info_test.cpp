// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestRulesetInfo, EmptyRulesetInfo)
{
    ddwaf::parameter root;
    ruleset_info info;
    info.to_object(root);

    auto root_map = static_cast<ddwaf::parameter::map>(root);
    EXPECT_EQ(root_map.size(), 0);

    ddwaf_object_free(&root);
}

TEST(TestRulesetInfo, ValidRulesetInfo)
{
    ddwaf::parameter root;
    {
        ruleset_info info;
        info.set_ruleset_version("2.3.4");

        {
            auto &section = info.add_section("rules");
            section.add_loaded("first");
        }

        {
            auto &section = info.add_section("exclusions");
            section.add_loaded("second");
        }

        {
            auto &section = info.add_section("rules_override");
            section.add_loaded("third");
        }
        info.to_object(root);
    }

    auto root_map = static_cast<ddwaf::parameter::map>(root);
    EXPECT_EQ(root_map.size(), 4);

    auto version = ddwaf::parser::at<std::string>(root_map, "ruleset_version");
    EXPECT_STREQ(version.c_str(), "2.3.4");

    std::unordered_map<std::string, std::string> kv{
        {"rules", "first"}, {"exclusions", "second"}, {"rules_override", "third"}};
    for (auto &[key, value] : kv) {
        auto section = ddwaf::parser::at<parameter::map>(root_map, key);
        EXPECT_EQ(section.size(), 3);

        auto loaded = ddwaf::parser::at<parameter::vector>(section, "loaded");
        EXPECT_EQ(loaded.size(), 1);

        EXPECT_STREQ(static_cast<std::string>(loaded[0]).c_str(), value.c_str());

        auto failed = ddwaf::parser::at<parameter::vector>(section, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(section, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    ddwaf_object_free(&root);
}

TEST(TestRulesetInfo, FailedWithErrorsRulesetInfo)
{
    ddwaf::parameter root;
    {
        ruleset_info info;
        info.set_ruleset_version("2.3.4");

        auto &section = info.add_section("rules");
        section.add_failed("first", "error1");
        section.add_failed("second", "error1");
        section.add_failed("third", "error2");
        section.add_failed("fourth", "error2");
        section.add_failed("fifth", "error3");

        info.to_object(root);
    }

    auto root_map = static_cast<ddwaf::parameter::map>(root);
    EXPECT_EQ(root_map.size(), 2);

    auto version = ddwaf::parser::at<std::string>(root_map, "ruleset_version");
    EXPECT_STREQ(version.c_str(), "2.3.4");

    auto section = ddwaf::parser::at<parameter::map>(root_map, "rules");
    EXPECT_EQ(section.size(), 3);

    auto loaded = ddwaf::parser::at<parameter::vector>(section, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::parser::at<parameter::string_set>(section, "failed");
    EXPECT_EQ(failed.size(), 5);
    EXPECT_NE(failed.find("first"), failed.end());
    EXPECT_NE(failed.find("second"), failed.end());
    EXPECT_NE(failed.find("third"), failed.end());
    EXPECT_NE(failed.find("fourth"), failed.end());
    EXPECT_NE(failed.find("fifth"), failed.end());

    auto errors = ddwaf::parser::at<parameter::map>(section, "errors");
    EXPECT_EQ(errors.size(), 3);
    {
        auto it = errors.find("error1");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 2);
        EXPECT_NE(error_rules.find("first"), error_rules.end());
        EXPECT_NE(error_rules.find("second"), error_rules.end());
    }

    {
        auto it = errors.find("error2");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 2);
        EXPECT_NE(error_rules.find("third"), error_rules.end());
        EXPECT_NE(error_rules.find("fourth"), error_rules.end());
    }

    {
        auto it = errors.find("error3");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("fifth"), error_rules.end());
    }

    ddwaf_object_free(&root);
}

TEST(TestRulesetInfo, NullRulesetInfo)
{
    // This test just verifies there are no side-effects to the null ruleset info
    null_ruleset_info info;
    info.set_ruleset_version("1.2.3");

    {
        auto &section = info.add_section("rules");
        section.add_loaded("loaded");
        section.add_failed("failed", "error");
    }

    {
        auto &section = info.add_section("exclusions");
        section.add_loaded("loaded");
        section.add_failed("failed", "error");
    }

    EXPECT_TRUE(true);
}
