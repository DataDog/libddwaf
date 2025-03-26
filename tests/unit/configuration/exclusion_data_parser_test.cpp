// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/data_parser.hpp"

using namespace ddwaf;

namespace {

TEST(TestExclusionDataParser, ParseIPData)
{
    auto object = yaml_to_object<ddwaf_object>(
        R"([{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_exclusion_data(input, collector, section);
    ddwaf_object_free(&object);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("ip_data"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::exclusion_data);
    EXPECT_EQ(change.exclusion_data.size(), 1);

    EXPECT_EQ(cfg.exclusion_data.size(), 1);
    EXPECT_EQ(cfg.exclusion_data["ip_data"].type, data_type::ip_with_expiration);
}

TEST(TestExclusionDataParser, ParseStringData)
{
    auto object = yaml_to_object<ddwaf_object>(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_exclusion_data(input, collector, section);
    ddwaf_object_free(&object);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("usr_data"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::exclusion_data);
    EXPECT_EQ(change.exclusion_data.size(), 1);

    EXPECT_EQ(cfg.exclusion_data.size(), 1);
    EXPECT_EQ(cfg.exclusion_data["usr_data"].type, data_type::data_with_expiration);
}

TEST(TestExclusionDataParser, ParseMultipleData)
{
    auto object = yaml_to_object<ddwaf_object>(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_exclusion_data(input, collector, section);
    ddwaf_object_free(&object);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("ip_data"), loaded.end());
        EXPECT_NE(loaded.find("usr_data"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::exclusion_data);
    EXPECT_EQ(change.exclusion_data.size(), 2);

    EXPECT_EQ(cfg.exclusion_data.size(), 2);
    EXPECT_EQ(cfg.exclusion_data["usr_data"].type, data_type::data_with_expiration);
    EXPECT_EQ(cfg.exclusion_data["ip_data"].type, data_type::ip_with_expiration);
}

TEST(TestExclusionDataParser, ParseUnknownDataID)
{
    auto object = yaml_to_object<ddwaf_object>(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_exclusion_data(input, collector, section);
    ddwaf_object_free(&object);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("ip_data"), loaded.end());
        EXPECT_NE(loaded.find("usr_data"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::exclusion_data);
    EXPECT_EQ(change.exclusion_data.size(), 2);

    EXPECT_EQ(cfg.exclusion_data.size(), 2);
    EXPECT_EQ(cfg.exclusion_data["ip_data"].type, data_type::ip_with_expiration);
    EXPECT_EQ(cfg.exclusion_data["usr_data"].type, data_type::data_with_expiration);
}

TEST(TestExclusionDataParser, ParseUnsupportedTypes)
{
    auto object = yaml_to_object<ddwaf_object>(
        R"([{id: usr_data, type: blob_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: whatever, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_exclusion_data(input, collector, section);
    ddwaf_object_free(&object);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 2);
        EXPECT_NE(failed.find("ip_data"), failed.end());
        EXPECT_NE(failed.find("usr_data"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 2);
        {
            auto it = errors.find("unknown type: 'blob_with_expiration'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<raw_configuration::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_NE(error_rules.find("usr_data"), error_rules.end());
        }

        {
            auto it = errors.find("unknown type: 'whatever'");
            EXPECT_NE(it, errors.end());

            auto error_rules = static_cast<raw_configuration::string_set>(it->second);
            EXPECT_EQ(error_rules.size(), 1);
            EXPECT_NE(error_rules.find("ip_data"), error_rules.end());
        }
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
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestExclusionDataParser, ParseUnknownDataIDWithUnsupportedType)
{
    auto object = yaml_to_object<ddwaf_object>(
        R"([{id: usr_data, type: blob_with_expiration, data: [{value: user, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_exclusion_data(input, collector, section);
    ddwaf_object_free(&object);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("usr_data"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("unknown type: 'blob_with_expiration'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("usr_data"), error_rules.end());
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
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestExclusionDataParser, ParseMissingType)
{
    auto object = yaml_to_object<ddwaf_object>(
        R"([{id: ip_data, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_exclusion_data(input, collector, section);
    ddwaf_object_free(&object);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ip_data"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ip_data"), error_rules.end());
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
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestExclusionDataParser, ParseMissingID)
{
    auto object = yaml_to_object<ddwaf_object>(
        R"([{type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_exclusion_data(input, collector, section);
    ddwaf_object_free(&object);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

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
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

TEST(TestExclusionDataParser, ParseMissingData)
{
    auto object = yaml_to_object<ddwaf_object>(R"([{id: ip_data, type: ip_with_expiration}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_exclusion_data(input, collector, section);
    ddwaf_object_free(&object);

    {
        auto diagnostics = section.to_object();
        raw_configuration root{diagnostics};

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("ip_data"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'data'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("ip_data"), error_rules.end());
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
    EXPECT_TRUE(change.overrides_by_id.empty());
    EXPECT_TRUE(change.overrides_by_tags.empty());

    EXPECT_TRUE(cfg.actions.empty());
    EXPECT_TRUE(cfg.base_rules.empty());
    EXPECT_TRUE(cfg.user_rules.empty());
    EXPECT_TRUE(cfg.exclusion_data.empty());
    EXPECT_TRUE(cfg.rule_data.empty());
    EXPECT_TRUE(cfg.rule_filters.empty());
    EXPECT_TRUE(cfg.input_filters.empty());
    EXPECT_TRUE(cfg.processors.empty());
    EXPECT_TRUE(cfg.scanners.empty());
    EXPECT_TRUE(cfg.overrides_by_id.empty());
    EXPECT_TRUE(cfg.overrides_by_tags.empty());
}

} // namespace
