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

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

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

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);
}

TEST(TestParserV2InputFilters, ParseNoConditionsOrTargets)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(R"([{id: 1, inputs: [{address: http.client_ip}]}])");

    ddwaf::null_ruleset_info::null_section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    auto filters = parser::v2::parse_filters(filters_array, section, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(filters.rule_filters.size(), 0);
    EXPECT_EQ(filters.input_filters.size(), 1);

    const auto &input_it = filters.input_filters.begin();
    EXPECT_STR(input_it->first, "1");

    const auto &input = input_it->second;
    EXPECT_EQ(input.conditions.size(), 0);
    EXPECT_EQ(input.targets.size(), 0);
    EXPECT_TRUE(input.filter);
}

// TODO more tests
