// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/parser.hpp"
#include "test.h"

TEST(TestParserV2RuleData, ParseIPData)
{
    std::unordered_map<std::string, std::string> rule_data_ids{{"ip_data", "ip_match"}};

    auto object = readRule(
        R"([{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    parameter::vector input = parameter(object);

    auto rule_data = parser::v2::parse_rule_data(input, rule_data_ids);
    ddwaf_object_free(&object);

    EXPECT_EQ(rule_data.size(), 1);
    EXPECT_STRV(rule_data["ip_data"]->name(), "ip_match");
}

TEST(TestParserV2RuleData, ParseStringData)
{
    std::unordered_map<std::string, std::string> rule_data_ids{{"usr_data", "exact_match"}};

    auto object = readRule(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]}])");
    parameter::vector input = parameter(object);

    auto rule_data = parser::v2::parse_rule_data(input, rule_data_ids);
    ddwaf_object_free(&object);

    EXPECT_EQ(rule_data.size(), 1);
    EXPECT_STRV(rule_data["usr_data"]->name(), "exact_match");
}

TEST(TestParserV2RuleData, ParseMultipleRuleData)
{
    std::unordered_map<std::string, std::string> rule_data_ids{
        {"ip_data", "ip_match"}, {"usr_data", "exact_match"}};

    auto object = readRule(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    parameter::vector input = parameter(object);

    auto rule_data = parser::v2::parse_rule_data(input, rule_data_ids);
    ddwaf_object_free(&object);

    EXPECT_EQ(rule_data.size(), 2);
    EXPECT_STRV(rule_data["usr_data"]->name(), "exact_match");
    EXPECT_STRV(rule_data["ip_data"]->name(), "ip_match");
}

TEST(TestParserV2RuleData, ParseUnknownRuleData)
{
    std::unordered_map<std::string, std::string> rule_data_ids{{"usr_data", "exact_match"}};

    auto object = readRule(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    parameter::vector input = parameter(object);

    auto rule_data = parser::v2::parse_rule_data(input, rule_data_ids);
    ddwaf_object_free(&object);

    EXPECT_EQ(rule_data.size(), 1);
    EXPECT_STRV(rule_data["usr_data"]->name(), "exact_match");
}

TEST(TestParserV2RuleData, ParseUnsupportedProcessor)
{
    std::unordered_map<std::string, std::string> rule_data_ids{
        {"usr_data", "match_regex"}, {"ip_data", "phrase_match"}};

    auto object = readRule(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    parameter::vector input = parameter(object);

    auto rule_data = parser::v2::parse_rule_data(input, rule_data_ids);
    ddwaf_object_free(&object);

    EXPECT_EQ(rule_data.size(), 0);
}

TEST(TestParserV2RuleData, ParseMissingType)
{
    std::unordered_map<std::string, std::string> rule_data_ids{{"ip_data", "ip_match"}};

    auto object = readRule(R"([{id: ip_data, data: [{value: 192.168.1.1, expiration: 500}]}])");
    parameter::vector input = parameter(object);

    auto rule_data = parser::v2::parse_rule_data(input, rule_data_ids);
    ddwaf_object_free(&object);

    EXPECT_EQ(rule_data.size(), 0);
}

TEST(TestParserV2RuleData, ParseMissingID)
{
    std::unordered_map<std::string, std::string> rule_data_ids{{"ip_data", "ip_match"}};

    auto object =
        readRule(R"([{type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    parameter::vector input = parameter(object);

    auto rule_data = parser::v2::parse_rule_data(input, rule_data_ids);
    ddwaf_object_free(&object);

    EXPECT_EQ(rule_data.size(), 0);
}

TEST(TestParserV2RuleData, ParseMissingData)
{
    std::unordered_map<std::string, std::string> rule_data_ids{{"ip_data", "ip_match"}};

    auto object = readRule(R"([{id: ip_data, type: ip_with_expiration}])");
    parameter::vector input = parameter(object);

    auto rule_data = parser::v2::parse_rule_data(input, rule_data_ids);
    ddwaf_object_free(&object);

    EXPECT_EQ(rule_data.size(), 0);
}
