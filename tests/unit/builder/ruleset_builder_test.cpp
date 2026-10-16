// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <memory>
#include <string>

#include "builder/ruleset_builder.hpp"
#include "common/gtest_utils.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/configuration_manager.hpp"
#include "ruleset.hpp"
#include "ruleset_info.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

std::shared_ptr<ruleset> add_and_build(configuration_manager &manager,
    ddwaf::ruleset_builder &builder, const std::string &path, const std::string &yaml)
{
    auto object = yaml_to_object<owned_object>(yaml);
    raw_configuration config{object};
    ruleset_info info;
    EXPECT_TRUE(manager.add_or_update(path, config, info));
    auto [spec, changes] = manager.consolidate();
    return builder.build(spec, changes);
}

TEST(TestRulesetBuilder, RuleTargetIndexOnlyRegeneratedWithRules)
{
    configuration_manager manager;
    ddwaf::ruleset_builder builder;

    auto initial = add_and_build(manager, builder, "rules",
        R"({version: '2.1', rules: [{id: rule1, name: rule1, tags: {type: flow, category: category}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: rule}}]}]})");
    ASSERT_TRUE(initial);
    EXPECT_FALSE(initial->rule_targets->find(get_target_index("arg1")).empty());

    // Exclusions don't affect the rules, so the index is reused
    auto excluded = add_and_build(manager, builder, "exclusions",
        R"({exclusions: [{id: exclusion1, rules_target: [{rule_id: rule1}]}]})");
    ASSERT_TRUE(excluded);
    EXPECT_EQ(excluded->rule_targets, initial->rule_targets);

    // Whereas new rules require a new index
    auto custom = add_and_build(manager, builder, "custom",
        R"({custom_rules: [{id: rule2, name: rule2, tags: {type: flow, category: category}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg2}], regex: rule}}]}]})");
    ASSERT_TRUE(custom);
    EXPECT_NE(custom->rule_targets, initial->rule_targets);
    EXPECT_FALSE(custom->rule_targets->find(get_target_index("arg1")).empty());
    EXPECT_FALSE(custom->rule_targets->find(get_target_index("arg2")).empty());
}

} // namespace
