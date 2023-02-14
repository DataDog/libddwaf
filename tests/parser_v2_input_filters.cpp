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

    parameter::vector exclusions_array = parameter(object);
    auto exclusions = parser::v2::parse_filters(exclusions_array, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(exclusions.unconditional_rule_filters.size(), 0);
    EXPECT_EQ(exclusions.rule_filters.size(), 0);
    EXPECT_EQ(exclusions.input_filters.size(), 0);
}

TEST(TestParserV2InputFilters, ParseDuplicateFilters)
{
    ddwaf::manifest manifest;
    ddwaf::object_limits limits;
    manifest.insert("http.client_ip");
    manifest.insert("usr.id");

    auto object = readRule(
        R"([{id: 1, inputs: [{address: http.client_ip}]}, {id: 1, inputs: [{address: usr.id}]}])");

    parameter::vector exclusions_array = parameter(object);
    auto exclusions = parser::v2::parse_filters(exclusions_array, manifest, limits);
    ddwaf_object_free(&object);

    EXPECT_EQ(exclusions.unconditional_rule_filters.size(), 0);
    EXPECT_EQ(exclusions.rule_filters.size(), 0);
    EXPECT_EQ(exclusions.input_filters.size(), 1);
}
