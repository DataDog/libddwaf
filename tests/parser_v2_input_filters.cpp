// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestParserV2InputFilters, ParseFilterWithoutID)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;

    auto object = readRule(R"([{inputs: [{address: http.client_ip}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 0);
}

TEST(TestParserV2InputFilters, ParseDuplicateFilters)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(
        R"([{id: 1, inputs: [{address: http.client_ip}]}, {id: 1, inputs: [{address: usr.id}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);
}

TEST(TestParserV2InputFilters, ParseUnconditionalNoTargets)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(R"([{id: 1, inputs: [{address: http.client_ip}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);

    const auto &filter_it = filters.input_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 0);
    EXPECT_EQ(filter.targets.size(), 0);
    EXPECT_TRUE(filter.filter);
}

TEST(TestParserV2InputFilters, ParseUnconditionalTargetID)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);

    const auto &filter_it = filters.input_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 0);
    EXPECT_EQ(filter.targets.size(), 1);
    EXPECT_TRUE(filter.filter);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::id);
    EXPECT_STR(target.rule_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestParserV2InputFilters, ParseUnconditionalTargetTags)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{tags: {type: rule, category: unknown}}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);

    const auto &filter_it = filters.input_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 0);
    EXPECT_EQ(filter.targets.size(), 1);
    EXPECT_TRUE(filter.filter);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::tags);
    EXPECT_TRUE(target.rule_id.empty());
    EXPECT_EQ(target.tags.size(), 2);
    EXPECT_STR(target.tags.find("type")->second, "rule");
    EXPECT_STR(target.tags.find("category")->second, "unknown");
}

TEST(TestParserV2InputFilters, ParseUnconditionalTargetPriority)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939, tags: {type: rule, category: unknown}}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);

    const auto &filter_it = filters.input_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 0);
    EXPECT_EQ(filter.targets.size(), 1);
    EXPECT_TRUE(filter.filter);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::id);
    EXPECT_STR(target.rule_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestParserV2InputFilters, ParseUnconditionalMultipleTargets)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}, {tags: {type: rule, category: unknown}}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);

    const auto &filter_it = filters.input_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 0);
    EXPECT_EQ(filter.targets.size(), 2);
    EXPECT_TRUE(filter.filter);

    {
        const auto &target = filter.targets[0];
        EXPECT_EQ(target.type, parser::target_type::id);
        EXPECT_STR(target.rule_id, "2939");
        EXPECT_EQ(target.tags.size(), 0);
    }

    {
        const auto &target = filter.targets[1];
        EXPECT_EQ(target.type, parser::target_type::tags);
        EXPECT_TRUE(target.rule_id.empty());
        EXPECT_EQ(target.tags.size(), 2);
        EXPECT_STR(target.tags.find("type")->second, "rule");
        EXPECT_STR(target.tags.find("category")->second, "unknown");
    }
}

TEST(TestParserV2InputFilters, ParseMultipleUnconditional)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}]}, {id: 2, inputs: [{address: usr.id}], rules_target: [{tags: {type: rule, category: unknown}}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("1"), loaded.end());
        EXPECT_NE(loaded.find("2"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 2);

    {
        const auto &filter_it = filters.input_filters.find("1");
        EXPECT_STR(filter_it->first, "1");

        const auto &filter = filter_it->second;
        EXPECT_EQ(filter.conditions.size(), 0);
        EXPECT_EQ(filter.targets.size(), 1);
        EXPECT_TRUE(filter.filter);

        const auto &target = filter.targets[0];
        EXPECT_EQ(target.type, parser::target_type::id);
        EXPECT_STR(target.rule_id, "2939");
        EXPECT_EQ(target.tags.size(), 0);
    }

    {
        const auto &filter_it = filters.input_filters.find("2");
        EXPECT_STR(filter_it->first, "2");

        const auto &filter = filter_it->second;
        EXPECT_EQ(filter.conditions.size(), 0);
        EXPECT_EQ(filter.targets.size(), 1);
        EXPECT_TRUE(filter.filter);

        const auto &target = filter.targets[0];
        EXPECT_EQ(target.type, parser::target_type::tags);
        EXPECT_TRUE(target.rule_id.empty());
        EXPECT_EQ(target.tags.size(), 2);
        EXPECT_STR(target.tags.find("type")->second, "rule");
        EXPECT_STR(target.tags.find("category")->second, "unknown");
    }
}

TEST(TestParserV2InputFilters, ParseConditionalSingleCondition)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);

    const auto &filter_it = filters.input_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 1);
    EXPECT_EQ(filter.targets.size(), 1);
    EXPECT_TRUE(filter.filter);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::id);
    EXPECT_STR(target.rule_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestParserV2InputFilters, ParseConditionalMultipleConditions)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(
        R"([{id: 1, inputs: [{address: http.client_ip}], rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    ddwaf::ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);

    const auto &filter_it = filters.input_filters.begin();
    EXPECT_STR(filter_it->first, "1");

    const auto &filter = filter_it->second;
    EXPECT_EQ(filter.conditions.size(), 3);
    EXPECT_EQ(filter.targets.size(), 1);
    EXPECT_TRUE(filter.filter);

    const auto &target = filter.targets[0];
    EXPECT_EQ(target.type, parser::target_type::id);
    EXPECT_STR(target.rule_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}
