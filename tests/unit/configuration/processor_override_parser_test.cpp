// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/processor_override_parser.hpp"

using namespace ddwaf;

namespace {

TEST(TestProcessorOverrideParser, ParseOverrideWithoutTargets)
{
    auto object = yaml_to_object(R"([{"target":[], "scanners":[]}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processor_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("index:0"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("processor override without targets");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
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
    EXPECT_TRUE(change.rule_overrides_by_id.empty());
    EXPECT_TRUE(change.rule_overrides_by_tags.empty());
    EXPECT_TRUE(change.processor_overrides.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_id.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_tags.empty());
    EXPECT_TRUE(cfg.processor_overrides.empty());
}

TEST(TestProcessorOverrideParser, ParseOverrideWithTargetByTags)
{
    auto object = yaml_to_object(R"([{"target":[{"tags": {"type": "value"}}], "scanners":[]}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processor_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("index:0"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("processor override with target by tags not supported");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
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
    EXPECT_TRUE(change.rule_overrides_by_id.empty());
    EXPECT_TRUE(change.rule_overrides_by_tags.empty());
    EXPECT_TRUE(change.processor_overrides.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_id.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_tags.empty());
    EXPECT_TRUE(cfg.processor_overrides.empty());
}

TEST(TestProcessorOverrideParser, ParseOverrideWithoutScanners)
{
    auto object = yaml_to_object(R"([{"target":[{"id":"extract-content"}], "scanners":[]}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processor_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("index:0"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::processor_overrides);

    EXPECT_EQ(change.processor_overrides.size(), 1);
    EXPECT_EQ(cfg.processor_overrides.size(), 1);

    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.rule_overrides_by_id.empty());
    EXPECT_TRUE(change.rule_overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_id.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_tags.empty());
}

TEST(TestProcessorOverrideParser, ParseOverrideWithScannerById)
{
    auto object = yaml_to_object(
        R"([{"target":[{"id":"extract-content"}], "scanners": [{"id": "scanner-001"}]}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processor_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("index:0"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::processor_overrides);

    EXPECT_EQ(change.processor_overrides.size(), 1);
    EXPECT_EQ(cfg.processor_overrides.size(), 1);

    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.rule_overrides_by_id.empty());
    EXPECT_TRUE(change.rule_overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_id.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_tags.empty());
}

TEST(TestProcessorOverrideParser, ParseOverrideWithScannerByTags)
{
    auto object = yaml_to_object(
        R"([{"target":[{"id":"extract-content"}], "scanners": [{"tags": {"type":"email"}}]}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processor_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("index:0"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::processor_overrides);

    EXPECT_EQ(change.processor_overrides.size(), 1);
    EXPECT_EQ(cfg.processor_overrides.size(), 1);

    EXPECT_TRUE(change.actions.empty());
    EXPECT_TRUE(change.base_rules.empty());
    EXPECT_TRUE(change.user_rules.empty());
    EXPECT_TRUE(change.exclusion_data.empty());
    EXPECT_TRUE(change.rule_data.empty());
    EXPECT_TRUE(change.rule_filters.empty());
    EXPECT_TRUE(change.input_filters.empty());
    EXPECT_TRUE(change.processors.empty());
    EXPECT_TRUE(change.scanners.empty());
    EXPECT_TRUE(change.rule_overrides_by_id.empty());
    EXPECT_TRUE(change.rule_overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_id.empty());
    EXPECT_TRUE(cfg.rule_overrides_by_tags.empty());
}

} // namespace
