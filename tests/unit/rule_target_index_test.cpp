// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <bit>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "matcher/exact_match.hpp"
#include "module_category.hpp"
#include "rule_target_index.hpp"
#include "ruleset.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

using rule_set = rule_target_index::rule_set;

core_rule make_rule(const std::string &id, const std::vector<std::string> &targets,
    const std::string &module = "waf", std::vector<rule_attribute> attributes = {},
    core_rule::source_type source = core_rule::source_type::base)
{
    test::expression_builder builder(targets.size());
    for (const auto &target : targets) {
        builder.start_condition();
        builder.add_argument();
        builder.add_target(target);
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"value"});
    }

    return core_rule{id, id, {{"type", "type"}, {"category", "category"}, {"module", module}},
        builder.build(), {}, std::move(attributes), source};
}

std::shared_ptr<ruleset> make_ruleset(
    std::vector<core_rule> &&base, std::vector<core_rule> &&user = {})
{
    auto rs = std::make_shared<ruleset>();
    rs->insert_rules(std::make_shared<std::vector<core_rule>>(std::move(base)),
        std::make_shared<std::vector<core_rule>>(std::move(user)));
    return rs;
}

constexpr auto module_index(rule_module_category category)
{
    return static_cast<uint32_t>(category);
}

std::vector<rule_set> to_vector(std::span<const rule_set> sets)
{
    return {sets.begin(), sets.end()};
}

TEST(TestRuleTargetIndex, EmptyIndex)
{
    const rule_target_index index;
    EXPECT_TRUE(index.find(get_target_index("server.request.query")).empty());
    EXPECT_TRUE(index.unconditional_rules().empty());
}

TEST(TestRuleTargetIndex, UnknownTarget)
{
    std::vector<core_rule> rules;
    rules.emplace_back(make_rule("id", {"server.request.query"}));
    auto rs = make_ruleset(std::move(rules));

    EXPECT_TRUE(rs->rule_targets->find(get_target_index("server.request.body")).empty());
}

TEST(TestRuleTargetIndex, SingleRuleMultipleTargets)
{
    std::vector<core_rule> rules;
    rules.emplace_back(make_rule("id", {"server.request.query", "server.request.body"}));
    auto rs = make_ruleset(std::move(rules));

    const std::vector<rule_set> expected{
        {.module = module_index(rule_module_category::waf), .word = 0, .mask = 1}};
    EXPECT_EQ(
        to_vector(rs->rule_targets->find(get_target_index("server.request.query"))), expected);
    EXPECT_EQ(to_vector(rs->rule_targets->find(get_target_index("server.request.body"))), expected);
    EXPECT_TRUE(rs->rule_targets->unconditional_rules().empty());
}

TEST(TestRuleTargetIndex, RulesAcrossModules)
{
    std::vector<core_rule> rules;
    rules.emplace_back(make_rule("waf", {"http.client_ip"}));
    rules.emplace_back(make_rule("rasp", {"server.io.fs.file", "http.client_ip"}, "rasp"));
    rules.emplace_back(make_rule("acl", {"http.client_ip"}, "network-acl"));
    auto rs = make_ruleset(std::move(rules));

    // Rule sets are sorted by module
    EXPECT_EQ(to_vector(rs->rule_targets->find(get_target_index("http.client_ip"))),
        (std::vector<rule_set>{
            {.module = module_index(rule_module_category::network_acl), .word = 0, .mask = 1},
            {.module = module_index(rule_module_category::rasp), .word = 0, .mask = 1},
            {.module = module_index(rule_module_category::waf), .word = 0, .mask = 1},
        }));
    EXPECT_EQ(to_vector(rs->rule_targets->find(get_target_index("server.io.fs.file"))),
        (std::vector<rule_set>{
            {.module = module_index(rule_module_category::rasp), .word = 0, .mask = 1},
        }));
}

TEST(TestRuleTargetIndex, RulePositionsMatchModuleOrder)
{
    // The WAF module evaluates user rules before base rules
    std::vector<core_rule> base;
    base.emplace_back(make_rule("base", {"server.request.query"}));
    std::vector<core_rule> user;
    user.emplace_back(
        make_rule("user", {"server.request.body"}, "waf", {}, core_rule::source_type::user));
    auto rs = make_ruleset(std::move(base), std::move(user));

    const auto &waf = rs->rule_modules[module_index(rule_module_category::waf)];
    ASSERT_EQ(waf.get_rules().size(), 2);
    EXPECT_EQ(waf.get_rules()[0]->get_id(), "user");
    EXPECT_EQ(waf.get_rules()[1]->get_id(), "base");

    EXPECT_EQ(to_vector(rs->rule_targets->find(get_target_index("server.request.body"))),
        (std::vector<rule_set>{
            {.module = module_index(rule_module_category::waf), .word = 0, .mask = 0b01}}));
    EXPECT_EQ(to_vector(rs->rule_targets->find(get_target_index("server.request.query"))),
        (std::vector<rule_set>{
            {.module = module_index(rule_module_category::waf), .word = 0, .mask = 0b10}}));
}

TEST(TestRuleTargetIndex, MoreRulesThanWordBits)
{
    std::vector<core_rule> rules;
    for (unsigned i = 0; i < 130; ++i) {
        // Every rule references the common target, odd rules the odd target
        std::vector<std::string> targets{"common"};
        if (i % 2 == 1) {
            targets.emplace_back("odd");
        }
        rules.emplace_back(make_rule("id" + std::to_string(i), targets));
    }
    auto rs = make_ruleset(std::move(rules));

    constexpr auto waf = module_index(rule_module_category::waf);
    EXPECT_EQ(to_vector(rs->rule_targets->find(get_target_index("common"))),
        (std::vector<rule_set>{
            {.module = waf, .word = 0, .mask = ~uint64_t{0}},
            {.module = waf, .word = 1, .mask = ~uint64_t{0}},
            {.module = waf, .word = 2, .mask = 0b11},
        }));

    // Rules are all equivalent, so their position within the module may not
    // match their insertion order, but each word has as many odd rules.
    auto odd = rs->rule_targets->find(get_target_index("odd"));
    ASSERT_EQ(odd.size(), 3);
    EXPECT_EQ(
        std::popcount(odd[0].mask) + std::popcount(odd[1].mask) + std::popcount(odd[2].mask), 65);
}

TEST(TestRuleTargetIndex, ManyTargets)
{
    std::vector<core_rule> rules;
    for (unsigned i = 0; i < 100; ++i) {
        rules.emplace_back(
            make_rule("id" + std::to_string(i), {"target" + std::to_string(i), "common"}));
    }
    auto rs = make_ruleset(std::move(rules));

    const auto &waf = rs->rule_modules[module_index(rule_module_category::waf)];
    for (std::size_t i = 0; i < waf.get_rules().size(); ++i) {
        // The rule's id identifies its target
        const auto target = "target" + std::string{waf.get_rules()[i]->get_id().substr(2)};
        EXPECT_EQ(to_vector(rs->rule_targets->find(get_target_index(target))),
            (std::vector<rule_set>{{.module = module_index(rule_module_category::waf),
                .word = static_cast<uint32_t>(i / 64),
                .mask = uint64_t{1} << (i % 64)}}));
    }
    EXPECT_EQ(rs->rule_targets->find(get_target_index("common")).size(), 2);
    EXPECT_TRUE(rs->rule_targets->find(get_target_index("target100")).empty());
}

TEST(TestRuleTargetIndex, AttributeTargets)
{
    std::vector<rule_attribute> attributes;
    attributes.emplace_back(
        rule_attribute{.value_or_target = rule_attribute::input_target{.name = "usr.id",
                           .index = get_target_index("usr.id"),
                           .key_path = {}},
            .key = "attr"});

    std::vector<core_rule> rules;
    rules.emplace_back(make_rule("id", {"server.request.query"}, "waf", std::move(attributes)));
    auto rs = make_ruleset(std::move(rules));

    // The index covers the same targets as the ruleset's rule addresses
    EXPECT_EQ(rs->rule_addresses.size(), 2);
    for (const auto &[target, name] : rs->rule_addresses) {
        EXPECT_FALSE(rs->rule_targets->find(target).empty()) << name;
    }
}

TEST(TestRuleTargetIndex, UnconditionalRules)
{
    std::vector<core_rule> rules;
    rules.emplace_back(make_rule("conditional", {"server.request.query"}));
    rules.emplace_back(make_rule("unconditional", {}, "network-acl"));
    auto rs = make_ruleset(std::move(rules));

    EXPECT_EQ(to_vector(rs->rule_targets->unconditional_rules()),
        (std::vector<rule_set>{
            {.module = module_index(rule_module_category::network_acl), .word = 0, .mask = 1}}));
}

TEST(TestRuleTargetIndex, ReusedOnlyWithIdenticalModules)
{
    std::vector<core_rule> rules;
    rules.emplace_back(make_rule("id", {"server.request.query"}));
    auto rs = make_ruleset(std::move(rules));
    EXPECT_TRUE(rs->rule_targets->is_valid_for(rs->rule_modules));

    {
        // Same rules, so the index is reused
        ruleset other;
        other.insert_rules(rs->base_rules, rs->user_rules, rs->rule_targets);
        EXPECT_EQ(other.rule_targets, rs->rule_targets);
    }

    {
        // Equivalent but different rules, so a new index is generated
        std::vector<core_rule> other_rules;
        other_rules.emplace_back(make_rule("id", {"server.request.query"}));

        ruleset other;
        other.insert_rules(std::make_shared<std::vector<core_rule>>(std::move(other_rules)),
            rs->user_rules, rs->rule_targets);
        EXPECT_FALSE(rs->rule_targets->is_valid_for(other.rule_modules));
        EXPECT_NE(other.rule_targets, rs->rule_targets);
        EXPECT_TRUE(other.rule_targets->is_valid_for(other.rule_modules));
    }
}

} // namespace
