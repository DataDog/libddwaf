// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"
#include "ruleset.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestRuleset, InsertSingleBaseRule)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto rules = std::make_shared<std::vector<core_rule>>();
    rules->emplace_back(
        core_rule{"id", "name", {{"type", "type0"}, {"category", "category0"}}, builder.build()});

    ddwaf::ruleset ruleset;
    ruleset.insert_rules(rules, std::make_shared<std::vector<core_rule>>());

    EXPECT_EQ(ruleset.base_rules->size(), 1);
    EXPECT_EQ(ruleset.user_rules->size(), 0);
    EXPECT_EQ(ruleset.rule_addresses.size(), 1);

    EXPECT_TRUE(ruleset.rule_addresses.contains(get_target_index("http.client_ip")));
}

TEST(TestRuleset, InsertSingleUserRule)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto rules = std::make_shared<std::vector<core_rule>>();
    rules->emplace_back(
        core_rule{"id", "name", {{"type", "type0"}, {"category", "category0"}}, builder.build()});

    ddwaf::ruleset ruleset;
    ruleset.insert_rules(std::make_shared<std::vector<core_rule>>(), rules);

    EXPECT_EQ(ruleset.base_rules->size(), 0);
    EXPECT_EQ(ruleset.user_rules->size(), 1);
    EXPECT_EQ(ruleset.rule_addresses.size(), 1);

    EXPECT_TRUE(ruleset.rule_addresses.contains(get_target_index("http.client_ip")));
}

TEST(TestRuleset, InsertBaseAndUserRule)
{
    auto base_rules = std::make_shared<std::vector<core_rule>>();
    auto user_rules = std::make_shared<std::vector<core_rule>>();

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        base_rules->emplace_back(core_rule{
            "id", "name", {{"type", "type0"}, {"category", "category0"}}, builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        user_rules->emplace_back(core_rule{
            "id2", "name", {{"type", "type0"}, {"category", "category0"}}, builder.build()});
    }

    ddwaf::ruleset ruleset;
    ruleset.insert_rules(base_rules, user_rules);

    EXPECT_EQ(ruleset.base_rules->size(), 1);
    EXPECT_EQ(ruleset.user_rules->size(), 1);
    EXPECT_EQ(ruleset.rule_addresses.size(), 2);

    EXPECT_TRUE(ruleset.rule_addresses.contains(get_target_index("http.client_ip")));
    EXPECT_TRUE(ruleset.rule_addresses.contains(get_target_index("usr.id")));
}

TEST(TestRuleset, InsertMultipleBaseAndUserRule)
{
    auto base_rules = std::make_shared<std::vector<core_rule>>();
    auto user_rules = std::make_shared<std::vector<core_rule>>();

    std::shared_ptr<ddwaf::expression> ip_expr;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        ip_expr = builder.build();
    }

    std::shared_ptr<ddwaf::expression> usr_expr;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        usr_expr = builder.build();
    }

    std::shared_ptr<ddwaf::expression> route_expr;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.route");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"unrouted"});
        route_expr = builder.build();
    }

    base_rules->emplace_back(
        core_rule{"1", "name", {{"type", "type0"}, {"category", "category0"}}, ip_expr});
    base_rules->emplace_back(
        core_rule{"2", "name", {{"type", "type0"}, {"category", "category0"}}, usr_expr});
    base_rules->emplace_back(
        core_rule{"3", "name", {{"type", "type0"}, {"category", "category0"}}, usr_expr});
    base_rules->emplace_back(
        core_rule{"4", "name", {{"type", "type0"}, {"category", "category0"}}, ip_expr});
    user_rules->emplace_back(
        core_rule{"5", "name", {{"type", "type0"}, {"category", "category0"}}, route_expr});
    user_rules->emplace_back(
        core_rule{"6", "name", {{"type", "type0"}, {"category", "category0"}}, ip_expr});
    user_rules->emplace_back(
        core_rule{"7", "name", {{"type", "type0"}, {"category", "category0"}}, route_expr});
    user_rules->emplace_back(
        core_rule{"8", "name", {{"type", "type0"}, {"category", "category0"}}, ip_expr});

    ddwaf::ruleset ruleset;
    ruleset.insert_rules(base_rules, user_rules);

    EXPECT_EQ(ruleset.base_rules->size(), 4);
    EXPECT_EQ(ruleset.user_rules->size(), 4);
    EXPECT_EQ(ruleset.rule_addresses.size(), 3);

    EXPECT_TRUE(ruleset.rule_addresses.contains(get_target_index("http.client_ip")));
    EXPECT_TRUE(ruleset.rule_addresses.contains(get_target_index("usr.id")));
    EXPECT_TRUE(ruleset.rule_addresses.contains(get_target_index("http.route")));
}

} // namespace
