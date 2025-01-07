// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/exclusion_parser.hpp"
#include "parameter.hpp"

using namespace ddwaf;

namespace {

auto find_filter(const std::vector<rule_filter_spec> &filters, std::string_view id)
{
    for (auto it = filters.begin(); it != filters.end(); ++it) {
        if (it->id == id) {
            return it;
        }
    }
    return filters.end();
}

TEST(TestRuleFilterParser, ParseEmptyFilter)
{
    object_limits limits;

    auto object = yaml_to_object(R"([{id: 1}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("empty exclusion filter");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestRuleFilterParser, ParseFilterWithoutID)
{
    object_limits limits;

    auto object = yaml_to_object(R"([{rules_target: [{rule_id: 2939}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_filters(filters_array, cfg, ids, section, limits));
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

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestRuleFilterParser, ParseDuplicateUnconditional)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939}]},{id: 1, rules_target: [{tags: {type: rule, category: unknown}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("duplicate filter");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestRuleFilterParser, ParseUnconditionalTargetID)
{
    object_limits limits;

    auto object = yaml_to_object(R"([{id: 1, rules_target: [{rule_id: 2939}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 0);
    EXPECT_EQ(filter_it->targets.size(), 1);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::id);
    EXPECT_STR(target.ref_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestRuleFilterParser, ParseUnconditionalTargetTags)
{
    object_limits limits;

    auto object =
        yaml_to_object(R"([{id: 1, rules_target: [{tags: {type: rule, category: unknown}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 0);
    EXPECT_EQ(filter_it->targets.size(), 1);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::tags);
    EXPECT_TRUE(target.ref_id.empty());
    EXPECT_EQ(target.tags.size(), 2);
    EXPECT_STR(target.tags.find("type")->second, "rule");
    EXPECT_STR(target.tags.find("category")->second, "unknown");
}

TEST(TestRuleFilterParser, ParseUnconditionalTargetPriority)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939, tags: {type: rule, category: unknown}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 0);
    EXPECT_EQ(filter_it->targets.size(), 1);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::id);
    EXPECT_STR(target.ref_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestRuleFilterParser, ParseUnconditionalMultipleTargets)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939},{tags: {type: rule, category: unknown}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 0);
    EXPECT_EQ(filter_it->targets.size(), 2);

    {
        const auto &target = filter_it->targets[0];
        EXPECT_EQ(target.type, reference_type::id);
        EXPECT_STR(target.ref_id, "2939");
        EXPECT_EQ(target.tags.size(), 0);
    }

    {
        const auto &target = filter_it->targets[1];
        EXPECT_EQ(target.type, reference_type::tags);
        EXPECT_TRUE(target.ref_id.empty());
        EXPECT_EQ(target.tags.size(), 2);
        EXPECT_STR(target.tags.find("type")->second, "rule");
        EXPECT_STR(target.tags.find("category")->second, "unknown");
    }
}

TEST(TestRuleFilterParser, ParseMultipleUnconditional)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939}]},{id: 2, rules_target: [{tags: {type: rule, category: unknown}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("1"), loaded.end());
        EXPECT_NE(loaded.find("2"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 2);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    {
        const auto &filter_it = find_filter(cfg.rule_filters, "1");
        EXPECT_STR(filter_it->id, "1");

        EXPECT_EQ(filter_it->expr->size(), 0);
        EXPECT_EQ(filter_it->targets.size(), 1);

        const auto &target = filter_it->targets[0];
        EXPECT_EQ(target.type, reference_type::id);
        EXPECT_STR(target.ref_id, "2939");
        EXPECT_EQ(target.tags.size(), 0);
    }

    {
        const auto &filter_it = find_filter(cfg.rule_filters, "2");
        EXPECT_STR(filter_it->id, "2");

        EXPECT_EQ(filter_it->expr->size(), 0);
        EXPECT_EQ(filter_it->targets.size(), 1);

        const auto &target = filter_it->targets[0];
        EXPECT_EQ(target.type, reference_type::tags);
        EXPECT_TRUE(target.ref_id.empty());
        EXPECT_EQ(target.tags.size(), 2);
        EXPECT_STR(target.tags.find("type")->second, "rule");
        EXPECT_STR(target.tags.find("category")->second, "unknown");
    }
}

TEST(TestRuleFilterParser, ParseDuplicateConditional)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]},{id: 1, rules_target: [{tags: {type: rule, category: unknown}}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestRuleFilterParser, ParseConditionalSingleCondition)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 1);
    EXPECT_EQ(filter_it->targets.size(), 1);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::id);
    EXPECT_STR(target.ref_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestRuleFilterParser, ParseConditionalGlobal)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 1);
    EXPECT_EQ(filter_it->targets.size(), 0);
    EXPECT_EQ(filter_it->on_match, exclusion::filter_mode::bypass);
}

TEST(TestRuleFilterParser, ParseConditionalMultipleConditions)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939}], conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [x]}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2, key_path: [y]}], regex: .*}}]}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->expr->size(), 3);
    EXPECT_EQ(filter_it->targets.size(), 1);
    EXPECT_EQ(filter_it->on_match, exclusion::filter_mode::bypass);

    const auto &target = filter_it->targets[0];
    EXPECT_EQ(target.type, reference_type::id);
    EXPECT_STR(target.ref_id, "2939");
    EXPECT_EQ(target.tags.size(), 0);
}

TEST(TestRuleFilterParser, ParseOnMatchMonitor)
{
    object_limits limits;

    auto object =
        yaml_to_object(R"([{id: 1, rules_target: [{rule_id: 2939}], on_match: monitor}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->on_match, exclusion::filter_mode::monitor);
}

TEST(TestRuleFilterParser, ParseOnMatchBypass)
{
    object_limits limits;

    auto object = yaml_to_object(R"([{id: 1, rules_target: [{rule_id: 2939}], on_match: bypass}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->on_match, exclusion::filter_mode::bypass);
}

TEST(TestRuleFilterParser, ParseCustomOnMatch)
{
    object_limits limits;

    auto object =
        yaml_to_object(R"([{id: 1, rules_target: [{rule_id: 2939}], on_match: obliterate}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);

    const auto &filter_it = cfg.rule_filters.begin();
    EXPECT_STR(filter_it->id, "1");

    EXPECT_EQ(filter_it->on_match, exclusion::filter_mode::custom);
    EXPECT_STR(filter_it->custom_action, "obliterate");
}

TEST(TestRuleFilterParser, ParseInvalidOnMatch)
{
    object_limits limits;

    auto object = yaml_to_object(R"([{id: 1, rules_target: [{rule_id: 2939}], on_match: ""}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("1"), failed.end());

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 1);
        auto it = errors.find("empty on_match value");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestRuleFilterParser, IncompatibleMinVersion)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939}], min_version: 99.0.0, on_match: monitor}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto skipped = at<parameter::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_NE(skipped.find("1"), skipped.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestRuleFilterParser, IncompatibleMaxVersion)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939}], max_version: 0.0.99, on_match: monitor}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_FALSE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto skipped = at<parameter::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 1);
        EXPECT_NE(skipped.find("1"), skipped.end());

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 0);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

TEST(TestRuleFilterParser, CompatibleVersion)
{
    object_limits limits;

    auto object = yaml_to_object(
        R"([{id: 1, rules_target: [{rule_id: 2939}], min_version: 0.0.99, max_version: 2.0.0, on_match: monitor}])");

    configuration_spec cfg;
    spec_id_tracker ids;
    ruleset_info::section_info section;
    auto filters_array = static_cast<parameter::vector>(parameter(object));
    ASSERT_TRUE(parse_filters(filters_array, cfg, ids, section, limits));
    ddwaf_object_free(&object);

    {
        parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("1"), loaded.end());

        auto skipped = at<parameter::string_set>(root_map, "skipped");
        EXPECT_EQ(skipped.size(), 0);

        auto failed = at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(cfg.rule_filters.size(), 1);
    EXPECT_EQ(cfg.input_filters.size(), 0);
}

} // namespace
