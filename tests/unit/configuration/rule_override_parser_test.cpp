// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/rule_override_parser.hpp"

using namespace ddwaf;

namespace {

TEST(TestRuleOverrideParser, ParseRuleOverrideWithoutSideEffects)
{
    auto object = yaml_to_object(R"([{rules_target: [{tags: {confidence: 1}}]}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_rule_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

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

        auto it = errors.find("rule override without side-effects");
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

TEST(TestRuleOverrideParser, ParseRuleOverrideWithoutTargets)
{
    auto object = yaml_to_object(R"([{rules_target: [{}], enabled: false}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_rule_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

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

        auto it = errors.find("rule override with no targets");
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

TEST(TestRuleOverrideParser, ParseRuleOverride)
{
    auto object =
        yaml_to_object(R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_rule_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("index:0"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(change.rule_overrides_by_id.size(), 0);
    EXPECT_EQ(change.rule_overrides_by_tags.size(), 1);

    EXPECT_EQ(cfg.rule_overrides_by_id.size(), 0);
    EXPECT_EQ(cfg.rule_overrides_by_tags.size(), 1);

    auto &ovrd = cfg.rule_overrides_by_tags.begin()->second;
    EXPECT_FALSE(ovrd.enabled.has_value());
    EXPECT_TRUE(ovrd.actions.has_value());
    EXPECT_EQ(ovrd.actions->size(), 1);
    EXPECT_STR((*ovrd.actions)[0], "block");
    EXPECT_EQ(ovrd.targets.size(), 1);

    auto &target = ovrd.targets[0];
    EXPECT_EQ(target.type, reference_type::tags);
    EXPECT_TRUE(target.ref_id.empty());
    EXPECT_EQ(target.tags.size(), 1);
    EXPECT_STR(target.tags["confidence"], "1");
}

TEST(TestRuleOverrideParser, ParseMultipleRuleOverrides)
{
    auto object = yaml_to_object(
        R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]},{rules_target: [{rule_id: 1}], enabled: false}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_rule_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("index:0"), loaded.end());
        EXPECT_NE(loaded.find("index:1"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(change.rule_overrides_by_id.size(), 1);
    EXPECT_EQ(change.rule_overrides_by_tags.size(), 1);

    EXPECT_EQ(cfg.rule_overrides_by_id.size(), 1);
    EXPECT_EQ(cfg.rule_overrides_by_tags.size(), 1);

    {
        auto &ovrd = cfg.rule_overrides_by_tags.begin()->second;
        EXPECT_FALSE(ovrd.enabled.has_value());
        EXPECT_TRUE(ovrd.actions.has_value());
        EXPECT_EQ(ovrd.actions->size(), 1);
        EXPECT_STR((*ovrd.actions)[0], "block");
        EXPECT_EQ(ovrd.targets.size(), 1);

        auto &target = ovrd.targets[0];
        EXPECT_EQ(target.type, reference_type::tags);
        EXPECT_TRUE(target.ref_id.empty());
        EXPECT_EQ(target.tags.size(), 1);
        EXPECT_STR(target.tags["confidence"], "1");
    }

    {
        auto &ovrd = cfg.rule_overrides_by_id.begin()->second;
        EXPECT_TRUE(ovrd.enabled.has_value());
        EXPECT_FALSE(*ovrd.enabled);
        EXPECT_FALSE(ovrd.actions.has_value());
        EXPECT_EQ(ovrd.targets.size(), 1);

        auto &target = ovrd.targets[0];
        EXPECT_EQ(target.type, reference_type::id);
        EXPECT_STR(target.ref_id, "1");
        EXPECT_EQ(target.tags.size(), 0);
    }
}

TEST(TestRuleOverrideParser, ParseInconsistentRuleOverride)
{
    auto object = yaml_to_object(
        R"([{rules_target: [{tags: {confidence: 1}}, {rule_id: 1}], on_match: [block], enabled: false}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_rule_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

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

        auto it = errors.find("rule override targets rules and tags");
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

TEST(TestRuleOverrideParser, ParseRuleOverrideForTags)
{
    auto object = yaml_to_object(
        R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block], tags: {category: new_category, threshold: 25}}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_rule_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

    {
        raw_configuration root;
        section.to_object(root);

        auto root_map = static_cast<raw_configuration::map>(root);

        auto loaded = at<raw_configuration::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("index:0"), loaded.end());

        auto failed = at<raw_configuration::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = at<raw_configuration::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(change.rule_overrides_by_id.size(), 0);
    EXPECT_EQ(change.rule_overrides_by_tags.size(), 1);

    EXPECT_EQ(cfg.rule_overrides_by_id.size(), 0);
    EXPECT_EQ(cfg.rule_overrides_by_tags.size(), 1);

    auto &ovrd = cfg.rule_overrides_by_tags.begin()->second;
    EXPECT_FALSE(ovrd.enabled.has_value());
    EXPECT_TRUE(ovrd.actions.has_value());
    EXPECT_EQ(ovrd.actions->size(), 1);
    EXPECT_STR((*ovrd.actions)[0], "block");
    EXPECT_EQ(ovrd.targets.size(), 1);
    EXPECT_EQ(ovrd.tags.size(), 2);
    EXPECT_STR(ovrd.tags["category"], "new_category");
    EXPECT_STR(ovrd.tags["threshold"], "25");

    auto &target = ovrd.targets[0];
    EXPECT_EQ(target.type, reference_type::tags);
    EXPECT_TRUE(target.ref_id.empty());
    EXPECT_EQ(target.tags.size(), 1);
    EXPECT_STR(target.tags["confidence"], "1");
}

TEST(TestRuleOverrideParser, ParseInvalidTagsField)
{
    auto object = yaml_to_object(
        R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block], tags: [{category: new_category}, {threshold: 25}]}])");

    configuration_spec cfg;
    configuration_change_spec change;
    configuration_collector collector{change, cfg};
    ruleset_info::section_info section;
    auto override_array = static_cast<raw_configuration::vector>(raw_configuration(object));
    parse_rule_overrides(override_array, collector, section);
    ddwaf_object_free(&object);

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

        auto it = errors.find("bad cast, expected 'map', obtained 'array'");
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

} // namespace
