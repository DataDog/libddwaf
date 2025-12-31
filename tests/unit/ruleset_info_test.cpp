// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "configuration/common/common.hpp"
#include "ruleset_info.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestRulesetInfo, EmptyRulesetInfo)
{
    ruleset_info info;
    auto diagnostics = info.to_object();
    raw_configuration root{diagnostics};

    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);
    EXPECT_EQ(root_map.size(), 0);
}

TEST(TestRulesetInfo, ValidRulesetInfo)
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
        section.add_loaded(10);
    }

    auto diagnostics = info.to_object();
    raw_configuration root{diagnostics};

    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);
    EXPECT_EQ(root_map.size(), 4);

    auto version = at<std::string>(root_map, "ruleset_version");
    EXPECT_STREQ(version.c_str(), "2.3.4");

    std::unordered_map<std::string, std::string> kv{
        {"rules", "first"}, {"exclusions", "second"}, {"rules_override", "index:10"}};
    for (auto &[key, value] : kv) {
        auto section = at<raw_configuration::map>(root_map, key);
        EXPECT_EQ(section.size(), 5);

        auto loaded = at<raw_configuration::vector>(section, "loaded");
        EXPECT_EQ(loaded.size(), 1);

        EXPECT_STREQ(static_cast<std::string>(loaded[0]).c_str(), value.c_str());

        auto failed = at<raw_configuration::vector>(section, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::vector>(section, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = at<raw_configuration::map>(section, "errors");
        EXPECT_EQ(errors.size(), 0);
    }
}

TEST(TestRulesetInfo, FailedWithErrorsRulesetInfo)
{
    ruleset_info info;
    info.set_ruleset_version("2.3.4");

    {
        auto &section = info.add_section("rules");
        section.add_failed("first", parser_error_severity::error, "error1");
        section.add_failed("second", parser_error_severity::error, "error1");
        section.add_failed("third", parser_error_severity::error, "error2");
        section.add_failed("fourth", parser_error_severity::error, "error2");
        section.add_failed("fifth", parser_error_severity::error, "error3");
    }

    auto diagnostics = info.to_object();
    raw_configuration root{diagnostics};

    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);
    EXPECT_EQ(root_map.size(), 2);

    auto version = at<std::string>(root_map, "ruleset_version");
    EXPECT_STREQ(version.c_str(), "2.3.4");

    auto section = at<raw_configuration::map>(root_map, "rules");
    EXPECT_EQ(section.size(), 5);

    auto loaded = at<raw_configuration::vector>(section, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = at<raw_configuration::string_set>(section, "failed");
    EXPECT_EQ(failed.size(), 5);
    EXPECT_NE(failed.find("first"), failed.end());
    EXPECT_NE(failed.find("second"), failed.end());
    EXPECT_NE(failed.find("third"), failed.end());
    EXPECT_NE(failed.find("fourth"), failed.end());
    EXPECT_NE(failed.find("fifth"), failed.end());

    auto skipped = at<raw_configuration::vector>(section, "skipped");
    EXPECT_EQ(skipped.size(), 0);

    auto errors = at<raw_configuration::map>(section, "errors");
    EXPECT_EQ(errors.size(), 3);
    {
        auto it = errors.find("error1");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 2);
        EXPECT_NE(error_rules.find("first"), error_rules.end());
        EXPECT_NE(error_rules.find("second"), error_rules.end());
    }

    {
        auto it = errors.find("error2");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 2);
        EXPECT_NE(error_rules.find("third"), error_rules.end());
        EXPECT_NE(error_rules.find("fourth"), error_rules.end());
    }

    {
        auto it = errors.find("error3");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("fifth"), error_rules.end());
    }
}

TEST(TestRulesetInfo, SkippedRulesetInfo)
{
    ruleset_info info;
    info.set_ruleset_version("2.3.4");

    {
        auto &section = info.add_section("rules");
        section.add_skipped("first");
        section.add_skipped("second");
        section.add_skipped("third");
        section.add_skipped("fourth");
        section.add_skipped("fifth");
        section.add_skipped(5);
    }

    auto diagnostics = info.to_object();
    raw_configuration root{diagnostics};

    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);
    EXPECT_EQ(root_map.size(), 2);

    auto version = at<std::string>(root_map, "ruleset_version");
    EXPECT_STREQ(version.c_str(), "2.3.4");

    auto section = at<raw_configuration::map>(root_map, "rules");
    EXPECT_EQ(section.size(), 5);

    auto loaded = at<raw_configuration::vector>(section, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = at<raw_configuration::string_set>(section, "failed");
    EXPECT_EQ(failed.size(), 0);

    auto skipped = at<raw_configuration::vector>(section, "skipped");
    EXPECT_EQ(skipped.size(), 6);

    auto errors = at<raw_configuration::map>(section, "errors");
    EXPECT_EQ(errors.size(), 0);

    auto warnings = at<raw_configuration::map>(section, "warnings");
    EXPECT_EQ(warnings.size(), 0);
}

TEST(TestRulesetInfo, SectionErrorRulesetInfo)
{
    ruleset_info info;
    info.set_ruleset_version("2.3.4");

    {
        auto &section = info.add_section("rules_data");
        section.set_error("expected 'array' found 'map'");
        section.add_loaded("fourth");
        section.add_failed("fifth", parser_error_severity::error, "error");
    }

    auto diagnostics = info.to_object();
    raw_configuration root{diagnostics};

    {
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);
        EXPECT_EQ(root_map.size(), 2);

        auto version = at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "2.3.4");

        auto section = at<raw_configuration::map>(root_map, "rules_data");
        EXPECT_EQ(section.size(), 1);

        auto error = at<std::string>(section, "error");
        EXPECT_STR(error, "expected 'array' found 'map'");
    }
}

} // namespace
