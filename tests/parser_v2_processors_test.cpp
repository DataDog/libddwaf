// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/common.hpp"
#include "parser/parser.hpp"
#include "test_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestParserV2Processors, ParseNoGenerator)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(R"([{id: 1}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'generator'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParseNoID)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(R"([{}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("index:0"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'id'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParseNoParameters)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(R"([{id: 1, generator: extract_schema}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'parameters'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParseNoMappings)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(R"([{id: 1, generator: extract_schema, parameters: {}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'mappings'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParseEmptyMappings)
{
    ddwaf::object_limits limits;

    auto object =
        yaml_to_object(R"([{id: 1, generator: extract_schema, parameters: {mappings: []}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("empty mappings");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParseNoInput)
{
    ddwaf::object_limits limits;

    auto object =
        yaml_to_object(R"([{id: 1, generator: extract_schema, parameters: {mappings: [{}]}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'inputs'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParseEmptyInput)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [], output: out}]}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("empty processor input mapping");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParseNoOutput)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}]}]}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'output'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParseUnknownGenerator)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: unknown, parameters: {mappings: [{inputs: [{address: in}], output: out}]}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("unknown generator 'unknown'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParseUseless)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: false, output: false}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("processor not used for evaluation or output");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(processors.size(), 0);
}

TEST(TestParserV2Processors, ParsePreprocessor)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: true, output: false}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(processors.size(), 1);
    EXPECT_EQ(processors.pre.size(), 1);
    EXPECT_EQ(processors.post.size(), 0);
}

TEST(TestParserV2Processors, ParsePreprocessorWithOutput)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: true, output: true}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(processors.size(), 1);
    EXPECT_EQ(processors.pre.size(), 1);
    EXPECT_EQ(processors.post.size(), 0);
}

TEST(TestParserV2Processors, ParsePostprocessor)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: false, output: true}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(processors.size(), 1);
    EXPECT_EQ(processors.pre.size(), 0);
    EXPECT_EQ(processors.post.size(), 1);
}

TEST(TestParserV2Processors, ParseDuplicate)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: false, output: true},{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}], output: out}]}, evaluate: true, output: false}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto processors = parser::v2::parse_processors(array, section, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(processors.size(), 1);
    EXPECT_EQ(processors.pre.size(), 0);
    EXPECT_EQ(processors.post.size(), 1);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("duplicate processor");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }
}

} // namespace
