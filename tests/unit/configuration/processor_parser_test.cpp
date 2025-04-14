// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/processor_parser.hpp"

using namespace ddwaf;

namespace {

TEST(TestProcessorParser, ParseNoGenerator)
{
    auto object = yaml_to_object(R"([{id: 1}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'generator'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

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

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParseNoID)
{
    auto object = yaml_to_object(R"([{}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
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
        auto it = errors.find("missing key 'id'");
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

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParseNoParameters)
{
    auto object = yaml_to_object(R"([{id: 1, generator: extract_schema}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'parameters'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

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

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParseNoMappings)
{
    auto object = yaml_to_object(R"([{id: 1, generator: extract_schema, parameters: {}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'mappings'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

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

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParseEmptyMappings)
{
    auto object =
        yaml_to_object(R"([{id: 1, generator: extract_schema, parameters: {mappings: []}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("empty mappings");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

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

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParseNoInput)
{
    auto object =
        yaml_to_object(R"([{id: 1, generator: extract_schema, parameters: {mappings: [{}]}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'inputs'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

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

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParseEmptyInput)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [], output: out}]}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("empty processor input mapping");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

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

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParseNoOutput)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}]}]}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'output'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

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

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParseUnknownGenerator)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: unknown, parameters: {mappings: [{inputs: [{address: in}], output: out}]}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto warnings = at<raw_configuration::map>(root_map, "warnings");
        EXPECT_EQ(warnings.size(), 1);
        auto it = warnings.find("unknown generator: 'unknown'");
        EXPECT_NE(it, warnings.end());

        auto warning_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(warning_rules.size(), 1);
        EXPECT_NE(warning_rules.find("1"), warning_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParseUseless)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: false, output: false}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("processor not used for evaluation or output");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

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

    EXPECT_EQ(cfg.processors.size(), 0);
}

TEST(TestProcessorParser, ParsePreprocessor)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: true, output: false}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    EXPECT_EQ(change.content, change_set::processors);
    EXPECT_EQ(change.processors.size(), 1);
    EXPECT_TRUE(change.processors.contains("1"));
    EXPECT_EQ(cfg.processors.size(), 1);
    EXPECT_TRUE(cfg.processors.contains("1"));
}

TEST(TestProcessorParser, ParsePreprocessorWithOutput)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: true, output: true}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    EXPECT_EQ(change.content, change_set::processors);
    EXPECT_EQ(change.processors.size(), 1);
    EXPECT_TRUE(change.processors.contains("1"));
    EXPECT_EQ(cfg.processors.size(), 1);
    EXPECT_TRUE(cfg.processors.contains("1"));
}

TEST(TestProcessorParser, ParsePostprocessor)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: false, output: true}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    EXPECT_EQ(change.content, change_set::processors);
    EXPECT_EQ(change.processors.size(), 1);
    EXPECT_TRUE(change.processors.contains("1"));
    EXPECT_EQ(cfg.processors.size(), 1);
    EXPECT_TRUE(cfg.processors.contains("1"));
}

TEST(TestProcessorParser, ParseDuplicate)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: false, output: true},{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: true, output: false}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    EXPECT_EQ(change.content, change_set::processors);
    EXPECT_EQ(change.processors.size(), 1);
    EXPECT_TRUE(change.processors.contains("1"));
    EXPECT_EQ(cfg.processors.size(), 1);
    EXPECT_TRUE(cfg.processors.contains("1"));

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("duplicate processor");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }
}

TEST(TestProcessorParser, IncompatibleMinVersion)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, min_version: 99.0.0, evaluate: false, output: true}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

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

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_NE(skipped.find("1"), skipped.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }
}

TEST(TestProcessorParser, IncompatibleMaxVersion)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, max_version: 0.0.99, evaluate: false, output: true}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

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

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_NE(skipped.find("1"), skipped.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }
}

TEST(TestProcessorParser, CompatibleVersion)
{
    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, min_version: 0.0.99, max_version: 2.0.0, evaluate: false, output: true}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_processors(array, collector, section);
    ddwaf_object_free(&object);

    EXPECT_EQ(change.content, change_set::processors);
    EXPECT_EQ(change.processors.size(), 1);
    EXPECT_TRUE(change.processors.contains("1"));
    EXPECT_EQ(cfg.processors.size(), 1);
    EXPECT_TRUE(cfg.processors.contains("1"));

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }
}

} // namespace
