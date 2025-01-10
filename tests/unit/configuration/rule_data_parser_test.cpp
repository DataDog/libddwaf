// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/data_parser.hpp"
#include "parameter.hpp"

using namespace ddwaf;

namespace {

auto find_data(const std::vector<data_spec> &data_vec, std::string_view id)
{
    for (const auto &data : data_vec) {
        if (data.data_id == id) {
            return data;
        }
    }
    throw;
}

TEST(TestRuleDataParser, ParseIPData)
{
    auto object = yaml_to_object(
        R"([{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    configuration_spec cfg;
    ruleset_info::section_info section;
    ASSERT_TRUE(parse_rule_data(input, cfg, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ip_data"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_data.size(), 1);
    EXPECT_EQ(find_data(cfg.rule_data, "ip_data").type, data_type::ip_with_expiration);
}

TEST(TestRuleDataParser, ParseStringData)
{
    auto object = yaml_to_object(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    configuration_spec cfg;
    ruleset_info::section_info section;
    ASSERT_TRUE(parse_rule_data(input, cfg, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("usr_data"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_data.size(), 1);
    EXPECT_EQ(find_data(cfg.rule_data, "usr_data").type, data_type::data_with_expiration);
}

TEST(TestRuleDataParser, ParseMultipleData)
{
    auto object = yaml_to_object(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    configuration_spec cfg;
    ruleset_info::section_info section;
    ASSERT_TRUE(parse_rule_data(input, cfg, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("ip_data"), loaded.end());
        EXPECT_NE(loaded.find("usr_data"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_data.size(), 2);
    EXPECT_EQ(find_data(cfg.rule_data, "usr_data").type, data_type::data_with_expiration);
    EXPECT_EQ(find_data(cfg.rule_data, "ip_data").type, data_type::ip_with_expiration);
}

TEST(TestRuleDataParser, ParseUnknownDataID)
{
    auto object = yaml_to_object(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    configuration_spec cfg;
    ruleset_info::section_info section;
    ASSERT_TRUE(parse_rule_data(input, cfg, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("ip_data"), loaded.end());
        EXPECT_NE(loaded.find("usr_data"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_data.size(), 2);
    EXPECT_EQ(find_data(cfg.rule_data, "ip_data").type, data_type::ip_with_expiration);
    EXPECT_EQ(find_data(cfg.rule_data, "usr_data").type, data_type::data_with_expiration);
}

TEST(TestRuleDataParser, ParseUnsupportedTypes)
{
    auto object = yaml_to_object(
        R"([{id: usr_data, type: blob_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: whatever, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    configuration_spec cfg;
    ruleset_info::section_info section;
    ASSERT_FALSE(parse_rule_data(input, cfg, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 2);
        EXPECT_NE(failed.find("ip_data"), failed.end());
        EXPECT_NE(failed.find("usr_data"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 2);
        {
            auto it = errors.find("unknown type 'blob_with_expiration'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_NE(error_rules.find("usr_data"), error_rules.end());
        }

        {
            auto it = errors.find("unknown type 'whatever'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<parameter::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_NE(error_rules.find("ip_data"), error_rules.end());
        }

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_data.size(), 0);
}

TEST(TestRuleDataParser, ParseUnknownDataIDWithUnsupportedType)
{
    auto object = yaml_to_object(
        R"([{id: usr_data, type: blob_with_expiration, data: [{value: user, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    configuration_spec cfg;
    ruleset_info::section_info section;
    ASSERT_FALSE(parse_rule_data(input, cfg, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("usr_data"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("unknown type 'blob_with_expiration'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("usr_data"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_data.size(), 0);
}

TEST(TestRuleDataParser, ParseMissingType)
{
    auto object =
        yaml_to_object(R"([{id: ip_data, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    configuration_spec cfg;
    ruleset_info::section_info section;
    ASSERT_FALSE(parse_rule_data(input, cfg, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ip_data"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ip_data"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_data.size(), 0);
}

TEST(TestRuleDataParser, ParseMissingID)
{
    auto object = yaml_to_object(
        R"([{type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    configuration_spec cfg;
    ruleset_info::section_info section;
    ASSERT_FALSE(parse_rule_data(input, cfg, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("index:0"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'id'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_data.size(), 0);
}

TEST(TestRuleDataParser, ParseMissingData)
{
    auto object = yaml_to_object(R"([{id: ip_data, type: ip_with_expiration}])");
    auto input = static_cast<parameter::vector>(parameter(object));

    configuration_spec cfg;
    ruleset_info::section_info section;
    ASSERT_FALSE(parse_rule_data(input, cfg, section));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ip_data"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'data'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ip_data"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_data.size(), 0);
}
} // namespace
