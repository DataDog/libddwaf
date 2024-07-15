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

TEST(TestParserV2RulesOverride, ParseRuleOverrideWithoutSideEffects)
{
    auto object = yaml_to_object(R"([{rules_target: [{tags: {confidence: 1}}]}])");

    ddwaf::ruleset_info::section_info section;
    auto override_array = static_cast<parameter::vector>(parameter(object));
    auto overrides = parser::v2::parse_overrides(override_array, section);
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

        auto it = errors.find("rule override without side-effects");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());

        ddwaf_object_free(&root);
    }
}

TEST(TestParserV2RulesOverride, ParseRuleOverrideWithoutTargets)
{
    auto object = yaml_to_object(R"([{rules_target: [{}], enabled: false}])");

    ddwaf::ruleset_info::section_info section;
    auto override_array = static_cast<parameter::vector>(parameter(object));
    auto overrides = parser::v2::parse_overrides(override_array, section);
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

        auto it = errors.find("rule override with no targets");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());

        ddwaf_object_free(&root);
    }
}

TEST(TestParserV2RulesOverride, ParseRuleOverride)
{
    auto object =
        yaml_to_object(R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]}])");

    ddwaf::ruleset_info::section_info section;
    auto override_array = static_cast<parameter::vector>(parameter(object));
    auto overrides = parser::v2::parse_overrides(override_array, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("index:0"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(overrides.by_ids.size(), 0);
    EXPECT_EQ(overrides.by_tags.size(), 1);

    auto &ovrd = overrides.by_tags[0];
    EXPECT_FALSE(ovrd.enabled.has_value());
    EXPECT_TRUE(ovrd.actions.has_value());
    EXPECT_EQ(ovrd.actions->size(), 1);
    EXPECT_STR((*ovrd.actions)[0], "block");
    EXPECT_EQ(ovrd.targets.size(), 1);

    auto &target = ovrd.targets[0];
    EXPECT_EQ(target.type, parser::reference_type::tags);
    EXPECT_TRUE(target.ref_id.empty());
    EXPECT_EQ(target.tags.size(), 1);
    EXPECT_STR(target.tags["confidence"], "1");
}

TEST(TestParserV2RulesOverride, ParseMultipleRuleOverrides)
{
    auto object = yaml_to_object(
        R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]},{rules_target: [{rule_id: 1}], enabled: false}])");

    ddwaf::ruleset_info::section_info section;
    auto override_array = static_cast<parameter::vector>(parameter(object));
    auto overrides = parser::v2::parse_overrides(override_array, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 2);
        EXPECT_NE(loaded.find("index:0"), loaded.end());
        EXPECT_NE(loaded.find("index:1"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(overrides.by_ids.size(), 1);
    EXPECT_EQ(overrides.by_tags.size(), 1);

    {
        auto &ovrd = overrides.by_tags[0];
        EXPECT_FALSE(ovrd.enabled.has_value());
        EXPECT_TRUE(ovrd.actions.has_value());
        EXPECT_EQ(ovrd.actions->size(), 1);
        EXPECT_STR((*ovrd.actions)[0], "block");
        EXPECT_EQ(ovrd.targets.size(), 1);

        auto &target = ovrd.targets[0];
        EXPECT_EQ(target.type, parser::reference_type::tags);
        EXPECT_TRUE(target.ref_id.empty());
        EXPECT_EQ(target.tags.size(), 1);
        EXPECT_STR(target.tags["confidence"], "1");
    }

    {
        auto &ovrd = overrides.by_ids[0];
        EXPECT_TRUE(ovrd.enabled.has_value());
        EXPECT_FALSE(*ovrd.enabled);
        EXPECT_FALSE(ovrd.actions.has_value());
        EXPECT_EQ(ovrd.targets.size(), 1);

        auto &target = ovrd.targets[0];
        EXPECT_EQ(target.type, parser::reference_type::id);
        EXPECT_STR(target.ref_id, "1");
        EXPECT_EQ(target.tags.size(), 0);
    }
}

TEST(TestParserV2RulesOverride, ParseInconsistentRuleOverride)
{
    auto object = yaml_to_object(
        R"([{rules_target: [{tags: {confidence: 1}}, {rule_id: 1}], on_match: [block], enabled: false}])");

    ddwaf::ruleset_info::section_info section;
    auto override_array = static_cast<parameter::vector>(parameter(object));
    auto overrides = parser::v2::parse_overrides(override_array, section);
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

        auto it = errors.find("rule override targets rules and tags");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(overrides.by_ids.size(), 0);
    EXPECT_EQ(overrides.by_tags.size(), 0);
}

TEST(TestParserV2RulesOverride, ParseRuleOverrideForTags)
{
    auto object = yaml_to_object(
        R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block], tags: {category: new_category, threshold: 25}}])");

    ddwaf::ruleset_info::section_info section;
    auto override_array = static_cast<parameter::vector>(parameter(object));
    auto overrides = parser::v2::parse_overrides(override_array, section);
    ddwaf_object_free(&object);

    {
        ddwaf::parameter root;
        section.to_object(root);

        auto root_map = static_cast<parameter::map>(root);

        auto loaded = ddwaf::parser::at<parameter::string_set>(root_map, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("index:0"), loaded.end());

        auto failed = ddwaf::parser::at<parameter::string_set>(root_map, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::parser::at<parameter::map>(root_map, "errors");
        EXPECT_EQ(errors.size(), 0);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(overrides.by_ids.size(), 0);
    EXPECT_EQ(overrides.by_tags.size(), 1);

    auto &ovrd = overrides.by_tags[0];
    EXPECT_FALSE(ovrd.enabled.has_value());
    EXPECT_TRUE(ovrd.actions.has_value());
    EXPECT_EQ(ovrd.actions->size(), 1);
    EXPECT_STR((*ovrd.actions)[0], "block");
    EXPECT_EQ(ovrd.targets.size(), 1);
    EXPECT_EQ(ovrd.tags.size(), 2);
    EXPECT_STR(ovrd.tags["category"], "new_category");
    EXPECT_STR(ovrd.tags["threshold"], "25");

    auto &target = ovrd.targets[0];
    EXPECT_EQ(target.type, parser::reference_type::tags);
    EXPECT_TRUE(target.ref_id.empty());
    EXPECT_EQ(target.tags.size(), 1);
    EXPECT_STR(target.tags["confidence"], "1");
}

TEST(TestParserV2RulesOverride, ParseInvalidTagsField)
{
    auto object = yaml_to_object(
        R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block], tags: [{category: new_category}, {threshold: 25}]}])");

    ddwaf::ruleset_info::section_info section;
    auto override_array = static_cast<parameter::vector>(parameter(object));
    auto overrides = parser::v2::parse_overrides(override_array, section);
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

        auto it = errors.find("bad cast, expected 'map', obtained 'array'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("index:0"), error_rules.end());

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(overrides.by_ids.size(), 0);
    EXPECT_EQ(overrides.by_tags.size(), 0);
}

} // namespace
