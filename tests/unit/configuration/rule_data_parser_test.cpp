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
using namespace ddwaf::test;

namespace {

TEST(TestRuleDataParser, ParseIPData)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

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
    EXPECT_EQ(change.content, change_set::rule_data);
    EXPECT_EQ(change.rule_data.size(), 1);

    EXPECT_EQ(cfg.rule_data.size(), 1);
    EXPECT_EQ(cfg.rule_data["ip_data"].type, data_type::ip_with_expiration);
}

TEST(TestRuleDataParser, ParseStringData)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

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
    EXPECT_EQ(change.content, change_set::rule_data);
    EXPECT_EQ(change.rule_data.size(), 1);

    EXPECT_EQ(cfg.rule_data.size(), 1);
    EXPECT_EQ(cfg.rule_data["usr_data"].type, data_type::data_with_expiration);
}

TEST(TestRuleDataParser, ParseMultipleData)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

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
    EXPECT_EQ(change.content, change_set::rule_data);
    EXPECT_EQ(change.rule_data.size(), 2);

    EXPECT_EQ(cfg.rule_data.size(), 2);
    EXPECT_EQ(cfg.rule_data["usr_data"].type, data_type::data_with_expiration);
    EXPECT_EQ(cfg.rule_data["ip_data"].type, data_type::ip_with_expiration);
}

TEST(TestRuleDataParser, ParseUnknownDataID)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: usr_data, type: data_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

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
    EXPECT_EQ(change.content, change_set::rule_data);
    EXPECT_EQ(change.rule_data.size(), 2);

    EXPECT_EQ(cfg.rule_data.size(), 2);
    EXPECT_EQ(cfg.rule_data["ip_data"].type, data_type::ip_with_expiration);
    EXPECT_EQ(cfg.rule_data["usr_data"].type, data_type::data_with_expiration);
}

TEST(TestRuleDataParser, ParseUnsupportedTypes)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: usr_data, type: blob_with_expiration, data: [{value: user, expiration: 500}]},{id: ip_data, type: whatever, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

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
}

TEST(TestRuleDataParser, ParseUnknownDataIDWithUnsupportedType)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: usr_data, type: blob_with_expiration, data: [{value: user, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

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
}

TEST(TestRuleDataParser, ParseMissingType)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: ip_data, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

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
}

TEST(TestRuleDataParser, ParseMissingID)
{
    auto object = yaml_to_object<owned_object>(
        R"([{type: ip_with_expiration, data: [{value: 192.168.1.1, expiration: 500}]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

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
}

TEST(TestRuleDataParser, ParseMissingData)
{
    auto object = yaml_to_object<owned_object>(R"([{id: ip_data, type: ip_with_expiration}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

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
}

TEST(TestRuleDataParser, ParseMalformedEntries)
{
    // Each data set fails because of a single malformed entry, the error
    // reported must be the same one the generic accessors produce.
    auto object = yaml_to_object<owned_object>(
        R"([
            {id: not_array, type: ip_with_expiration, data: {value: 1.2.3.4}},
            {id: not_map, type: ip_with_expiration, data: [{value: 1.2.3.4}, 1.2.3.5]},
            {id: no_value, type: data_with_expiration, data: [{value: a}, {expiration: 5}]},
            {id: bad_value, type: data_with_expiration, data: [{value: [a]}]},
            {id: null_value, type: data_with_expiration, data: [{value: null}]},
            {id: bad_expiration, type: data_with_expiration, data: [{value: a, expiration: soon}]},
            {id: neg_expiration, type: data_with_expiration, data: [{value: a, expiration: -1}]},
            {id: map_expiration, type: data_with_expiration, data: [{value: a, expiration: {}}]},
            {id: empty_key, type: data_with_expiration, data: [{"": x, value: a}]},
            {id: both_bad, type: data_with_expiration, data: [{value: [], expiration: []}]}
        ])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

    auto diagnostics = section.to_object();
    raw_configuration root{diagnostics};
    auto root_map = static_cast<raw_configuration::map>(root);

    auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = at<raw_configuration::string_set>(root_map, "failed");
    EXPECT_EQ(failed.size(), 10);

    auto errors = at<raw_configuration::map>(root_map, "errors");
    const std::vector<std::pair<std::string_view, std::vector<std::string_view>>> expected{
        {"bad cast, expected 'array', obtained 'map'", {"not_array"}},
        {"bad cast, expected 'map', obtained 'string'", {"not_map"}},
        {"missing key 'value'", {"no_value"}},
        {"invalid type 'array' for key 'value', expected 'string'", {"bad_value", "both_bad"}},
        {"invalid type 'null' for key 'value', expected 'string'", {"null_value"}},
        {"invalid type 'string' for key 'expiration', expected 'unsigned'", {"bad_expiration"}},
        {"invalid type 'signed' for key 'expiration', expected 'unsigned'", {"neg_expiration"}},
        {"invalid type 'map' for key 'expiration', expected 'unsigned'", {"map_expiration"}},
        {"malformed object, invalid key on map entry", {"empty_key"}},
    };
    EXPECT_EQ(errors.size(), expected.size());
    for (const auto &[error, ids] : expected) {
        auto it = errors.find(error);
        ASSERT_NE(it, errors.end()) << error;
        auto error_ids = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_ids.size(), ids.size()) << error;
        for (const auto &id : ids) { EXPECT_TRUE(error_ids.contains(id)) << error << ": " << id; }
    }

    EXPECT_TRUE(cfg.rule_data.empty());
}

TEST(TestRuleDataParser, ParseScalarValuesAndExpirations)
{
    auto object = yaml_to_object<owned_object>(
        R"([{id: usr_data, type: data_with_expiration, data: [
            {value: 42},
            {value: true, expiration: "500"},
            {value: -7, expiration: 0},
            {value: "", expiration: 10.0},
            {value: user, expiration: 600, other: [1, 2]}
        ]}])");
    auto input = static_cast<raw_configuration::vector>(raw_configuration(object));

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    parse_rule_data(input, collector, section);

    auto diagnostics = section.to_object();
    raw_configuration root{diagnostics};
    auto root_map = static_cast<raw_configuration::map>(root);
    auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
    EXPECT_EQ(loaded.size(), 1);
    EXPECT_TRUE(loaded.contains("usr_data"));

    ASSERT_EQ(cfg.rule_data.size(), 1);
    const auto &values = cfg.rule_data["usr_data"].values;
    std::vector<std::pair<std::string, uint64_t>> actual;
    for (const auto &[value, expiration] : values) { actual.emplace_back(value, expiration); }

    const std::vector<std::pair<std::string, uint64_t>> expected{
        {"42", 0}, {"true", 500}, {"-7", 0}, {"", 10}, {"user", 600}};
    EXPECT_EQ(actual, expected);
}

} // namespace
