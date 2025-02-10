// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/scanner_parser.hpp"

using namespace ddwaf;

namespace {

TEST(TestScannerParser, ParseKeyOnlyScanner)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ecd"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(change.content, change_set::scanners);
    EXPECT_EQ(change.scanners.size(), 1);
    EXPECT_TRUE(change.scanners.contains("ecd"));
    ASSERT_EQ(cfg.scanners.size(), 1);
    EXPECT_TRUE(cfg.scanners.contains("ecd"));

    const auto &scnr = cfg.scanners.at("ecd");
    EXPECT_STRV(scnr.get_id(), "ecd");
    std::unordered_map<std::string, std::string> tags{{"type", "email"}, {"category", "pii"}};
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object value;
    ddwaf_object_string(&value, "dog@datadoghq.com");
    EXPECT_TRUE(scnr.eval("email", value));
    EXPECT_FALSE(scnr.eval("mail", value));
    ddwaf_object_free(&value);

    ddwaf_object_string(&value, "ansodinsod");
    EXPECT_TRUE(scnr.eval("email", value));
    ddwaf_object_free(&value);
}

TEST(TestScannerParser, ParseValueOnlyScanner)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","value":{"operator":"match_regex","parameters":{"regex":"@"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ecd"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(change.content, change_set::scanners);
    EXPECT_EQ(change.scanners.size(), 1);
    EXPECT_TRUE(change.scanners.contains("ecd"));
    ASSERT_EQ(cfg.scanners.size(), 1);
    EXPECT_TRUE(cfg.scanners.contains("ecd"));

    const auto &scnr = cfg.scanners.at("ecd");
    EXPECT_STRV(scnr.get_id(), "ecd");
    std::unordered_map<std::string, std::string> tags{{"type", "email"}, {"category", "pii"}};
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object value;
    ddwaf_object_string(&value, "dog@datadoghq.com");
    EXPECT_TRUE(scnr.eval("email", value));
    EXPECT_TRUE(scnr.eval("mail", value));
    ddwaf_object_free(&value);

    ddwaf_object_string(&value, "ansodinsod");
    EXPECT_FALSE(scnr.eval("email", value));
    ddwaf_object_free(&value);
}

TEST(TestScannerParser, ParseKeyValueScanner)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"operator":"match_regex","parameters":{"regex":"@"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ecd"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(change.content, change_set::scanners);
    EXPECT_EQ(change.scanners.size(), 1);
    EXPECT_TRUE(change.scanners.contains("ecd"));
    ASSERT_EQ(cfg.scanners.size(), 1);
    EXPECT_TRUE(cfg.scanners.contains("ecd"));

    const auto &scnr = cfg.scanners.at("ecd");
    EXPECT_STRV(scnr.get_id(), "ecd");
    std::unordered_map<std::string, std::string> tags{{"type", "email"}, {"category", "pii"}};
    EXPECT_EQ(scnr.get_tags(), tags);

    ddwaf_object value;
    ddwaf_object_string(&value, "dog@datadoghq.com");
    EXPECT_TRUE(scnr.eval("email", value));
    EXPECT_FALSE(scnr.eval("mail", value));
    ddwaf_object_free(&value);

    ddwaf_object_string(&value, "ansodinsod");
    EXPECT_FALSE(scnr.eval("email", value));
    ddwaf_object_free(&value);
}

TEST(TestScannerParser, ParseNoID)
{
    auto definition = json_to_object(
        R"([{"key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"operator":"match_regex","parameters":{"regex":"@"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("index:0"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'id'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, ParseNoTags)
{
    auto definition = json_to_object(
        R"([{"id":"error","key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"operator":"match_regex","parameters":{"regex":"@"}}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("error"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'tags'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("error"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, ParseNoKeyValue)
{
    auto definition =
        json_to_object(R"([{"id":"error","tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("error"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("scanner has no key or value matcher");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("error"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, ParseDuplicate)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}},{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ecd"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("duplicate scanner");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(change.content, change_set::scanners);
    EXPECT_EQ(change.scanners.size(), 1);
    EXPECT_TRUE(change.scanners.contains("ecd"));
    ASSERT_EQ(cfg.scanners.size(), 1);
    EXPECT_TRUE(cfg.scanners.contains("ecd"));
}

TEST(TestScannerParser, ParseKeyNoOperator)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"parameters":{"regex":"email"}},"value":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);

    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'operator'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, ParseKeyNoParameters)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex"},"value":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'parameters'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, ParseValueNoOperator)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'operator'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, ParseValueNoParameters)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"value":{"operator":"match_regex"},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'parameters'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, ParseUnknownMatcher)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"what","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);

    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto warnings = at<raw_configuration::map>(root_map, "warnings");
        EXPECT_EQ(warnings.size(), 1);
        auto it = warnings.find("unknown operator: 'what'");
        EXPECT_NE(it, warnings.end());

        auto warning_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(warning_rules.size(), 1);
        EXPECT_NE(warning_rules.find("ecd"), warning_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, ParseRuleDataID)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"exact_match","parameters":{"data":"invalid"}},"tags":{"type":"email","category":"pii"}}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);

    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ecd"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("dynamic data on scanner condition");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ecd"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, IncompatibleMinVersion)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}, "min_version": "99.0.0"}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);

    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_TRUE(skipped.contains("ecd"));

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, IncompatibleMaxVersion)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}, "max_version": "0.0.99"}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);

    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_TRUE(skipped.contains("ecd"));

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_TRUE(change.empty());
    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestScannerParser, CompatibleVersion)
{
    auto definition = json_to_object(
        R"([{"id":"ecd","key":{"operator":"match_regex","parameters":{"regex":"email"}},"tags":{"type":"email","category":"pii"}, "min_version": "0.0.99", "max_version": "2.0.0"}])");
    auto scanners_array = static_cast<raw_configuration::vector>(raw_configuration(definition));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_scanners(scanners_array, collector, section);
    ddwaf_object_free(&definition);

    {
        ddwaf::raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("ecd"));

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(change.content, change_set::scanners);
    EXPECT_EQ(change.scanners.size(), 1);
    EXPECT_TRUE(change.scanners.contains("ecd"));
    ASSERT_EQ(cfg.scanners.size(), 1);
    EXPECT_TRUE(cfg.scanners.contains("ecd"));
}

} // namespace
