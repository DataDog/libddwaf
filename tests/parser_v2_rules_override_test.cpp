// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestParserV2RulesOverride, ParseRuleOverride)
{
    auto object = readRule(R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]}])");

    parameter::vector override_array = parameter(object);
    auto overrides = parser::v2::parse_overrides(override_array);
    ddwaf_object_free(&object);

    EXPECT_EQ(overrides.by_ids.size(), 0);
    EXPECT_EQ(overrides.by_tags.size(), 1);

    auto &ovrd = overrides.by_tags[0];
    EXPECT_FALSE(ovrd.enabled.has_value());
    EXPECT_TRUE(ovrd.actions.has_value());
    EXPECT_EQ(ovrd.actions->size(), 1);
    EXPECT_STR((*ovrd.actions)[0], "block");
    EXPECT_EQ(ovrd.targets.size(), 1);

    auto &target = ovrd.targets[0];
    EXPECT_EQ(target.type, parser::target_type::tags);
    EXPECT_TRUE(target.rule_id.empty());
    EXPECT_EQ(target.tags.size(), 1);
    EXPECT_STR(target.tags["confidence"], "1");
}

TEST(TestParserV2RulesOverride, ParseMultipleRuleOverrides)
{
    auto object = readRule(
        R"([{rules_target: [{tags: {confidence: 1}}], on_match: [block]},{rules_target: [{rule_id: 1}], enabled: false}])");

    parameter::vector override_array = parameter(object);
    auto overrides = parser::v2::parse_overrides(override_array);
    ddwaf_object_free(&object);

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
        EXPECT_EQ(target.type, parser::target_type::tags);
        EXPECT_TRUE(target.rule_id.empty());
        EXPECT_EQ(target.tags.size(), 1);
        // EXPECT_EQ(target.tags[0], {"confidence","1"});
    }

    {
        auto &ovrd = overrides.by_ids[0];
        EXPECT_TRUE(ovrd.enabled.has_value());
        EXPECT_FALSE(*ovrd.enabled);
        EXPECT_FALSE(ovrd.actions.has_value());
        EXPECT_EQ(ovrd.targets.size(), 1);

        auto &target = ovrd.targets[0];
        EXPECT_EQ(target.type, parser::target_type::id);
        EXPECT_STR(target.rule_id, "1");
        EXPECT_EQ(target.tags.size(), 0);
    }
}

TEST(TestParserV2RulesOverride, ParseInconsistentRuleOverride)
{
    auto object = readRule(
        R"([{rules_target: [{tags: {confidence: 1}}, {rule_id: 1}], on_match: [block], enabled: false}])");

    parameter::vector override_array = parameter(object);
    auto overrides = parser::v2::parse_overrides(override_array);
    ddwaf_object_free(&object);

    EXPECT_EQ(overrides.by_ids.size(), 0);
    EXPECT_EQ(overrides.by_tags.size(), 0);
}
