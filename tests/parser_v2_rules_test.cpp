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

TEST(TestParserV2Rules, ParseRule)
{
    ddwaf::object_limits limits;
    ddwaf::ruleset_info::section_info section;
    boost::unordered_flat_map<std::string, std::string> rule_data_ids;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    auto rules = parser::v2::parse_rules(rule_array, section, rule_data_ids, limits);
    ddwaf_object_free(&rule_object);

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

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(rules.size(), 1);
    EXPECT_NE(rules.find("1"), rules.end());

    parser::rule_spec &rule = rules["1"];
    EXPECT_TRUE(rule.enabled);
    EXPECT_EQ(rule.expr->size(), 3);
    EXPECT_EQ(rule.actions.size(), 0);
    EXPECT_STR(rule.name, "rule1");
    EXPECT_EQ(rule.tags.size(), 2);
    EXPECT_STR(rule.tags["type"], "flow1");
    EXPECT_STR(rule.tags["category"], "category1");
}

TEST(TestParserV2Rules, ParseRuleWithoutType)
{
    ddwaf::object_limits limits;
    ddwaf::ruleset_info::section_info section;
    boost::unordered_flat_map<std::string, std::string> rule_data_ids;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    auto rules = parser::v2::parse_rules(rule_array, section, rule_data_ids, limits);
    ddwaf_object_free(&rule_object);

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
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(rules.size(), 0);
}

TEST(TestParserV2Rules, ParseRuleInvalidTransformer)
{
    ddwaf::object_limits limits;
    ddwaf::ruleset_info::section_info section;
    boost::unordered_flat_map<std::string, std::string> rule_data_ids;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y], transformers: [unknown]}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    auto rules = parser::v2::parse_rules(rule_array, section, rule_data_ids, limits);
    ddwaf_object_free(&rule_object);

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
        auto it = errors.find("invalid transformer unknown");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(rules.size(), 0);
}
TEST(TestParserV2Rules, ParseRuleWithoutID)
{
    ddwaf::object_limits limits;
    ddwaf::ruleset_info::section_info section;
    boost::unordered_flat_map<std::string, std::string> rule_data_ids;

    auto rule_object = yaml_to_object(
        R"([{name: rule1, tags: {type: type1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    auto rules = parser::v2::parse_rules(rule_array, section, rule_data_ids, limits);
    ddwaf_object_free(&rule_object);

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

    EXPECT_EQ(rules.size(), 0);
}

TEST(TestParserV2Rules, ParseMultipleRules)
{
    ddwaf::object_limits limits;
    ddwaf::ruleset_info::section_info section;
    boost::unordered_flat_map<std::string, std::string> rule_data_ids;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 2);

    auto rules = parser::v2::parse_rules(rule_array, section, rule_data_ids, limits);
    ddwaf_object_free(&rule_object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("1"), loaded.end());
        EXPECT_NE(loaded.find("secondrule"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(rules.size(), 2);
    EXPECT_NE(rules.find("1"), rules.end());
    EXPECT_NE(rules.find("secondrule"), rules.end());

    {
        parser::rule_spec &rule = rules["1"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags["type"], "flow1");
        EXPECT_STR(rule.tags["category"], "category1");
    }

    {
        parser::rule_spec &rule = rules["secondrule"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 1);
        EXPECT_EQ(rule.actions.size(), 1);
        EXPECT_STR(rule.actions[0], "block");
        EXPECT_STR(rule.name, "rule2");
        EXPECT_EQ(rule.tags.size(), 3);
        EXPECT_STR(rule.tags["type"], "flow2");
        EXPECT_STR(rule.tags["category"], "category2");
        EXPECT_STR(rule.tags["confidence"], "none");
    }
}

TEST(TestParserV2Rules, ParseMultipleRulesOneInvalid)
{
    ddwaf::object_limits limits;
    ddwaf::ruleset_info::section_info section;
    boost::unordered_flat_map<std::string, std::string> rule_data_ids;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}, {id: error}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));

    auto rules = parser::v2::parse_rules(rule_array, section, rule_data_ids, limits);
    ddwaf_object_free(&rule_object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("1"), loaded.end());
        EXPECT_NE(loaded.find("secondrule"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("error"), failed.end());

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'conditions'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("error"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(rules.size(), 2);
    EXPECT_NE(rules.find("1"), rules.end());
    EXPECT_NE(rules.find("secondrule"), rules.end());

    {
        parser::rule_spec &rule = rules["1"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags["type"], "flow1");
        EXPECT_STR(rule.tags["category"], "category1");
    }

    {
        parser::rule_spec &rule = rules["secondrule"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 1);
        EXPECT_EQ(rule.actions.size(), 1);
        EXPECT_STR(rule.actions[0], "block");
        EXPECT_STR(rule.name, "rule2");
        EXPECT_EQ(rule.tags.size(), 3);
        EXPECT_STR(rule.tags["type"], "flow2");
        EXPECT_STR(rule.tags["category"], "category2");
        EXPECT_STR(rule.tags["confidence"], "none");
    }
}

TEST(TestParserV2Rules, ParseMultipleRulesOneDuplicate)
{
    ddwaf::object_limits limits;
    ddwaf::ruleset_info::section_info section;
    boost::unordered_flat_map<std::string, std::string> rule_data_ids;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: 1, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}])");

    auto rule_array = static_cast<parameter::vector>(parameter(rule_object));
    EXPECT_EQ(rule_array.size(), 2);

    auto rules = parser::v2::parse_rules(rule_array, section, rule_data_ids, limits);
    ddwaf_object_free(&rule_object);

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
        auto it = errors.find("duplicate rule");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(rules.size(), 1);
    EXPECT_NE(rules.find("1"), rules.end());

    {
        parser::rule_spec &rule = rules["1"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags["type"], "flow1");
        EXPECT_STR(rule.tags["category"], "category1");
    }
}
} // namespace
