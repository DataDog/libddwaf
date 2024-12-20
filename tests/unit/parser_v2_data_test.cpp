// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"

using namespace ddwaf;

namespace {

TEST(TestParserV2Data, ParseIPData)
{
    std::unordered_map<std::string, std::string> data_ids{{"ip_data", "ip_match"}};

    auto object = yaml_to_object(
        R"([{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    ddwaf::ruleset_info::section_info section;
    auto data_cfg = parser::v2::parse_data(input, data_ids, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ip_data"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(data_cfg.size(), 1);
    EXPECT_STRV(data_cfg["ip_data"]->name(), "ip_match");
}

TEST(TestParserV2Data, ParseStringData)
{
    std::unordered_map<std::string, std::string> data_ids{{"usr_data", "exact_match"}};

    auto object = yaml_to_object(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    ddwaf::ruleset_info::section_info section;
    auto data_cfg = parser::v2::parse_data(input, data_ids, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("usr_data"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(data_cfg.size(), 1);
    EXPECT_STRV(data_cfg["usr_data"]->name(), "exact_match");
}

TEST(TestParserV2Data, ParseMultipleData)
{
    std::unordered_map<std::string, std::string> data_ids{
        {"ip_data", "ip_match"}, {"usr_data", "exact_match"}};

    auto object = yaml_to_object(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    ddwaf::ruleset_info::section_info section;
    auto data_cfg = parser::v2::parse_data(input, data_ids, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("ip_data"), loaded.end());
        EXPECT_NE(loaded.find("usr_data"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(data_cfg.size(), 2);
    EXPECT_STRV(data_cfg["usr_data"]->name(), "exact_match");
    EXPECT_STRV(data_cfg["ip_data"]->name(), "ip_match");
}

TEST(TestParserV2Data, ParseUnknownDataID)
{
    std::unordered_map<std::string, std::string> data_ids{{"usr_data", "exact_match"}};

    auto object = yaml_to_object(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    ddwaf::ruleset_info::section_info section;
    auto data_cfg = parser::v2::parse_data(input, data_ids, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("ip_data"), loaded.end());
        EXPECT_NE(loaded.find("usr_data"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(data_cfg.size(), 2);
    EXPECT_STRV(data_cfg["ip_data"]->name(), "ip_match");
    EXPECT_STRV(data_cfg["usr_data"]->name(), "exact_match");
}

TEST(TestParserV2Data, ParseUnsupportedTypes)
{
    std::unordered_map<std::string, std::string> data_ids{
        {"usr_data", "match_regex"}, {"ip_data", "phrase_match"}};

    auto object = yaml_to_object(
        R"([{id: usr_data, type: blob_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: whatever, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    ddwaf::ruleset_info::section_info section;
    auto data_cfg = parser::v2::parse_data(input, data_ids, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 2);
        EXPECT_NE(failed.find("ip_data"), failed.end());
        EXPECT_NE(failed.find("usr_data"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 2);
        {
            auto it = errors.find("matcher match_regex doesn't support dynamic data");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_NE(error_rules.find("usr_data"), error_rules.end());
        }

        {
            auto it = errors.find("matcher phrase_match doesn't support dynamic data");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_NE(error_rules.find("ip_data"), error_rules.end());
        }

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(data_cfg.size(), 0);
}

TEST(TestParserV2Data, ParseUnknownDataIDWithUnsupportedType)
{
    std::unordered_map<std::string, std::string> data_ids{};

    auto object = yaml_to_object(
        R"([{id: usr_data, type: blob_with_expiration, data: [{value: user, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    ddwaf::ruleset_info::section_info section;
    auto data_cfg = parser::v2::parse_data(input, data_ids, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("usr_data"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("failed to infer matcher");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("usr_data"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(data_cfg.size(), 0);
}

TEST(TestParserV2Data, ParseMissingType)
{
    std::unordered_map<std::string, std::string> data_ids{{"ip_data", "ip_match"}};

    auto object =
        yaml_to_object(R"([{id: ip_data, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    ddwaf::ruleset_info::section_info section;
    auto data_cfg = parser::v2::parse_data(input, data_ids, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ip_data"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ip_data"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(data_cfg.size(), 0);
}

TEST(TestParserV2Data, ParseMissingID)
{
    std::unordered_map<std::string, std::string> data_ids{{"ip_data", "ip_match"}};

    auto object = yaml_to_object(
        R"([{type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    ddwaf::ruleset_info::section_info section;
    auto data_cfg = parser::v2::parse_data(input, data_ids, section);
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

    EXPECT_EQ(data_cfg.size(), 0);
}

TEST(TestParserV2Data, ParseMissingData)
{
    std::unordered_map<std::string, std::string> data_ids{{"ip_data", "ip_match"}};

    auto object = yaml_to_object(R"([{id: ip_data, type: ip_with_expiration}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    ddwaf::ruleset_info::section_info section;
    auto data_cfg = parser::v2::parse_data(input, data_ids, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ip_data"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'data'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ip_data"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(data_cfg.size(), 0);
}
} // namespace
