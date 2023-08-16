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

TEST(TestParserV2Preprocessors, ParseNoGenerator)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(R"([{id: 1}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto preprocessors = parser::v2::parse_preprocessors(array, section, limits);
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

    EXPECT_EQ(preprocessors.size(), 0);
}

TEST(TestParserV2Preprocessors, ParseNoID)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(R"([{}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto preprocessors = parser::v2::parse_preprocessors(array, section, limits);
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

    EXPECT_EQ(preprocessors.size(), 0);
}

TEST(TestParserV2Preprocessors, ParseNoParameters)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(R"([{id: 1, generator: extract_schema}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto preprocessors = parser::v2::parse_preprocessors(array, section, limits);
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

    EXPECT_EQ(preprocessors.size(), 0);
}

TEST(TestParserV2Preprocessors, ParseNoMappings)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(R"([{id: 1, generator: extract_schema, parameters: {}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto preprocessors = parser::v2::parse_preprocessors(array, section, limits);
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

    EXPECT_EQ(preprocessors.size(), 0);
}

TEST(TestParserV2Preprocessors, ParseEmptyMappings)
{
    ddwaf::object_limits limits;

    auto object =
        yaml_to_object(R"([{id: 1, generator: extract_schema, parameters: {mappings: []}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto preprocessors = parser::v2::parse_preprocessors(array, section, limits);
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

    EXPECT_EQ(preprocessors.size(), 0);
}

TEST(TestParserV2Preprocessors, ParseNoInput)
{
    ddwaf::object_limits limits;

    auto object =
        yaml_to_object(R"([{id: 1, generator: extract_schema, parameters: {mappings: [{}]}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto preprocessors = parser::v2::parse_preprocessors(array, section, limits);
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

    EXPECT_EQ(preprocessors.size(), 0);
}

TEST(TestParserV2Preprocessors, ParseEmptyInput)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [], output: out}]}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto preprocessors = parser::v2::parse_preprocessors(array, section, limits);
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
        auto it = errors.find("empty preprocessor input mapping");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(preprocessors.size(), 0);
}

TEST(TestParserV2Preprocessors, ParseNoOutput)
{
    ddwaf::object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, generator: extract_schema, parameters: {mappings: [{inputs: [{address: in}]}]}}])");

    ddwaf::ruleset_info::section_info section;
    auto array = static_cast<parameter::vector>(parameter(object));
    auto preprocessors = parser::v2::parse_preprocessors(array, section, limits);
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

    EXPECT_EQ(preprocessors.size(), 0);
}

} // namespace
