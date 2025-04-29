// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/rule_parser.hpp"

using namespace ddwaf;

namespace {

TEST(TestBaseRuleParser, ParseRule)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::rules);
    EXPECT_EQ(change.base_rules.size(), 1);
    EXPECT_TRUE(change.base_rules.contains("1"));

    EXPECT_EQ(cfg.base_rules.size(), 1);
    EXPECT_TRUE(cfg.base_rules.contains("1"));

    const rule_spec &rule = cfg.base_rules["1"];
    EXPECT_TRUE(rule.enabled);
    EXPECT_EQ(rule.expr->size(), 3);
    EXPECT_EQ(rule.actions.size(), 0);
    EXPECT_STR(rule.name, "rule1");
    EXPECT_EQ(rule.tags.size(), 2);
    EXPECT_STR(rule.tags.at("type"), "flow1");
    EXPECT_STR(rule.tags.at("category"), "category1");

    EXPECT_TRUE(change.actions.empty());
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

TEST(TestBaseRuleParser, ParseRuleWithoutType)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
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

TEST(TestBaseRuleParser, ParseRuleWithoutConditions)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: []}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);
    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("rule has no valid conditions");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        auto warnings = at<raw_configuration::map>(root_map, "warnings");
        EXPECT_EQ(warnings.size(), 0);

        ddwaf_object_free(&root);
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

TEST(TestBaseRuleParser, ParseRuleInvalidTransformer)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y], transformers: [unknown]}], regex: .*}}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        auto warnings = at<raw_configuration::map>(root_map, "warnings");
        EXPECT_EQ(warnings.size(), 1);
        auto it = warnings.find("unknown transformer: 'unknown'");
        EXPECT_NE(it, warnings.end());

        auto warning_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(warning_rules.size(), 1);
        EXPECT_NE(warning_rules.find("1"), warning_rules.end());

        ddwaf_object_free(&root);
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

TEST(TestBaseRuleParser, ParseRuleWithoutID)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{name: rule1, tags: {type: type1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

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

        ddwaf_object_free(&root);
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

TEST(TestBaseRuleParser, ParseMultipleRules)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    EXPECT_EQ(rule_array.size(), 2);

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("1"), loaded.end());
        EXPECT_NE(loaded.find("secondrule"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::rules);
    EXPECT_EQ(change.base_rules.size(), 2);
    EXPECT_TRUE(change.base_rules.contains("1"));
    EXPECT_TRUE(change.base_rules.contains("secondrule"));

    EXPECT_EQ(cfg.base_rules.size(), 2);
    EXPECT_TRUE(cfg.base_rules.contains("1"));
    EXPECT_TRUE(cfg.base_rules.contains("secondrule"));

    {
        const rule_spec &rule = cfg.base_rules["1"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags.at("type"), "flow1");
        EXPECT_STR(rule.tags.at("category"), "category1");
    }

    {
        const rule_spec &rule = cfg.base_rules["secondrule"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 1);
        EXPECT_EQ(rule.actions.size(), 1);
        EXPECT_STR(rule.actions[0], "block");
        EXPECT_STR(rule.name, "rule2");
        EXPECT_EQ(rule.tags.size(), 3);
        EXPECT_STR(rule.tags.at("type"), "flow2");
        EXPECT_STR(rule.tags.at("category"), "category2");
        EXPECT_STR(rule.tags.at("confidence"), "none");
    }
}

TEST(TestBaseRuleParser, ParseMultipleRulesOneInvalid)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: secondrule, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}, {id: error}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("1"), loaded.end());
        EXPECT_NE(loaded.find("secondrule"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("error"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("missing key 'conditions'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("error"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::rules);
    EXPECT_EQ(change.base_rules.size(), 2);
    EXPECT_TRUE(change.base_rules.contains("1"));
    EXPECT_TRUE(change.base_rules.contains("secondrule"));

    EXPECT_EQ(cfg.base_rules.size(), 2);
    EXPECT_TRUE(cfg.base_rules.contains("1"));
    EXPECT_TRUE(cfg.base_rules.contains("secondrule"));

    {
        const rule_spec &rule = cfg.base_rules["1"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags.at("type"), "flow1");
        EXPECT_STR(rule.tags.at("category"), "category1");
    }

    {
        const rule_spec &rule = cfg.base_rules["secondrule"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 1);
        EXPECT_EQ(rule.actions.size(), 1);
        EXPECT_STR(rule.actions[0], "block");
        EXPECT_STR(rule.name, "rule2");
        EXPECT_EQ(rule.tags.size(), 3);
        EXPECT_STR(rule.tags.at("type"), "flow2");
        EXPECT_STR(rule.tags.at("category"), "category2");
        EXPECT_STR(rule.tags.at("confidence"), "none");
    }
}

TEST(TestBaseRuleParser, ParseMultipleRulesOneDuplicate)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]},{id: 1, name: rule2, tags: {type: flow2, category: category2, confidence: none}, conditions: [{operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}], on_match: [block]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    EXPECT_EQ(rule_array.size(), 2);

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("duplicate rule");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::rules);
    EXPECT_EQ(change.base_rules.size(), 1);
    EXPECT_TRUE(change.base_rules.contains("1"));

    EXPECT_EQ(cfg.base_rules.size(), 1);
    EXPECT_TRUE(cfg.base_rules.contains("1"));

    {
        const rule_spec &rule = cfg.base_rules["1"];
        EXPECT_TRUE(rule.enabled);
        EXPECT_EQ(rule.expr->size(), 3);
        EXPECT_EQ(rule.actions.size(), 0);
        EXPECT_STR(rule.name, "rule1");
        EXPECT_EQ(rule.tags.size(), 2);
        EXPECT_STR(rule.tags.at("type"), "flow1");
        EXPECT_STR(rule.tags.at("category"), "category1");
    }
}

TEST(TestBaseRuleParser, KeyPathTooLong)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z]}], regex: .*}}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("key_path beyond maximum container depth");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
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

TEST(TestBaseRuleParser, NegatedMatcherTooManyParameters)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: "!match_regex", parameters: {inputs: [{address: arg1}, {address: arg2}], regex: .*}}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("multiple targets for non-variadic argument");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
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

TEST(TestBaseRuleParser, SupportedVersionedOperator)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{"id":"rsp-930-003","name":"SQLi Exploit detection","tags":{"type":"sqli","category":"exploit_detection","module":"rasp"},"conditions":[{"parameters":{"resource":[{"address":"server.db.statement"}],"params":[{"address":"server.request.query"},{"address":"server.request.body"},{"address":"server.request.path_params"},{"address":"grpc.server.request.message"},{"address":"graphql.server.all_resolvers"},{"address":"graphql.server.resolver"}],"db_type":[{"address":"server.db.system"}]},"operator":"sqli_detector@v2"}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("rsp-930-003"));

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::rules);
    EXPECT_EQ(change.base_rules.size(), 1);
    EXPECT_EQ(cfg.base_rules.size(), 1);
}

TEST(TestBaseRuleParser, UnsupportedVersionedOperator)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{"id":"rsp-930-003","name":"SQLi Exploit detection","tags":{"type":"sqli","category":"exploit_detection","module":"rasp"},"conditions":[{"parameters":{"resource":[{"address":"server.db.statement"}],"params":[{"address":"server.request.query"},{"address":"server.request.body"},{"address":"server.request.path_params"},{"address":"grpc.server.request.message"},{"address":"graphql.server.all_resolvers"},{"address":"graphql.server.resolver"}],"db_type":[{"address":"server.db.system"}]},"operator":"sqli_detector@v20"}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_TRUE(skipped.contains("rsp-930-003"));

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
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

TEST(TestBaseRuleParser, IncompatibleMinVersion)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, min_version: 99.0.0, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_TRUE(skipped.contains("1"));

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
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

TEST(TestBaseRuleParser, IncompatibleMaxVersion)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, max_version: 0.0.99, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_TRUE(skipped.contains("1"));

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
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

TEST(TestBaseRuleParser, CompatibleVersion)
{
    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;

    auto rule_object = yaml_to_object(
        R"([{id: 1, name: rule1, tags: {type: flow1, category: category1}, min_version: 0.0.99, max_version: 2.0.0, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    auto rule_array = static_cast<raw_configuration::vector>(raw_configuration(rule_object));
    EXPECT_EQ(rule_array.size(), 1);

    parse_base_rules(rule_array, collector, section);

    ddwaf_object_free(&rule_object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_TRUE(loaded.contains("1"));

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto skipped = at<raw_configuration::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_FALSE(change.empty());
    EXPECT_EQ(change.content, change_set::rules);
    EXPECT_EQ(change.base_rules.size(), 1);
    EXPECT_EQ(cfg.base_rules.size(), 1);
}

} // namespace
