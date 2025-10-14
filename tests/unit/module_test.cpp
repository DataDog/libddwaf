// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "clock.hpp"
#include "common/gtest_utils.hpp"
#include "condition/scalar_condition.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"
#include "module.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

bool contains(auto results, auto id)
{
    for (const auto &result : results) {
        if (result.event.has_value()) {
            if (result.event->rule.id == id) {
                return true;
            }
        }
    }
    return false;
}

TEST(TestModuleUngrouped, SingleRuleMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<core_rule>("id", "name", std::move(tags), builder.build());

    rule_module_builder mod_builder{base_rule_precedence, null_grouping_key};
    mod_builder.insert(rule.get());

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 1);
    }

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(root);
        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        mod.eval(results, store, cache, {}, {}, deadline);
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::none);
        EXPECT_EQ(results.size(), 0);
    }
}

TEST(TestModuleUngrouped, MultipleMonitoringRuleMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id2", "name", std::move(tags), builder.build()));
    }

    rule_module_builder mod_builder{base_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 2);
        EXPECT_TRUE(contains(results, "id1"));
        EXPECT_TRUE(contains(results, "id2"));
    }

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(root);
        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        mod.eval(results, store, cache, {}, {}, deadline);
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::none);
        EXPECT_EQ(results.size(), 0);
    }
}

TEST(TestModuleUngrouped, BlockingRuleMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id2"));
    }

    // No further calls should happen after a blocking rule matches
}

TEST(TestModuleUngrouped, MonitoringRuleMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.2"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id1"));
    }

    // Check that we can still match the blocking rule
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.2"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
    }
}

TEST(TestModuleUngrouped, BlockingRuleMatchBasePrecedence)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::user, core_rule::verdict_type::block));
        rules.emplace_back(
            std::make_shared<core_rule>("id", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id2"));
    }

    // No further calls should happen after a blocking rule matches
}

TEST(TestModuleUngrouped, BlockingRuleMatchUserPrecedence)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::user, core_rule::verdict_type::block));
        rules.emplace_back(
            std::make_shared<core_rule>("id", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{user_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id1"));
    }

    // No further calls should happen after a blocking rule matches
}

TEST(TestModuleUngrouped, NonExpiringModule)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<core_rule>("id", "name", std::move(tags), builder.build());

    rule_module_builder mod_builder{
        base_rule_precedence, null_grouping_key, rule_module::expiration_policy::non_expiring};
    mod_builder.insert(rule.get());

    auto mod = mod_builder.build();
    EXPECT_FALSE(mod.may_expire());

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline{0s};
        mod.eval(results, store, cache, {}, {}, deadline);

        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id"));
    }
}

TEST(TestModuleUngrouped, ExpiringModule)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<core_rule>("id", "name", std::move(tags), builder.build());

    rule_module_builder mod_builder{
        base_rule_precedence, null_grouping_key, rule_module::expiration_policy::expiring};
    mod_builder.insert(rule.get());

    auto mod = mod_builder.build();
    EXPECT_TRUE(mod.may_expire());

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline{0s};
        EXPECT_THROW(mod.eval(results, store, cache, {}, {}, deadline), ddwaf::timeout_exception);
    }
}

TEST(TestModuleUngrouped, DisabledRules)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::monitor, false));
    }

    rule_module_builder mod_builder{user_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::none);
    }
}

TEST(TestModuleGrouped, MultipleGroupsMonitoringRuleMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id2", "name", std::move(tags), builder.build()));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 2);
        EXPECT_TRUE(contains(results, "id1"));
        EXPECT_TRUE(contains(results, "id2"));
    }
}

TEST(TestModuleGrouped, MultipleGroupsBlockingRuleMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id2"));
    }
}

TEST(TestModuleGrouped, SingleGroupBlockingRuleMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id2"));
    }
}

TEST(TestModuleGrouped, SingleGroupMonitoringRuleMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id2", "name", std::move(tags), builder.build()));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id1"));
    }
}

TEST(TestModuleGrouped, UserPrecedenceSingleGroupMonitoringUserMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    rule_module_builder mod_builder{user_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id2"));
    }
}

TEST(TestModuleGrouped, BasePrecedenceSingleGroupMonitoringBaseMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id1"));
    }
}

TEST(TestModuleGrouped, UserPrecedenceSingleGroupBlockingBaseMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    rule_module_builder mod_builder{user_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id1"));
    }
}

TEST(TestModuleGrouped, UserPrecedenceSingleGroupBlockingUserMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::user, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{user_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id2"));
    }
}

TEST(TestModuleGrouped, BasePrecedenceSingleGroupBlockingBaseMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id1"));
    }
}

TEST(TestModuleGrouped, BasePrecedenceSingleGroupBlockingUserMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::user, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id2"));
    }
}

TEST(TestModuleGrouped, UserPrecedenceMultipleGroupsMonitoringMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    rule_module_builder mod_builder{user_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 2);
        EXPECT_TRUE(contains(results, "id1"));
        EXPECT_TRUE(contains(results, "id2"));
    }
}

TEST(TestModuleGrouped, UserPrecedenceMultipleGroupsBlockingMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::user, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{user_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id2"));
    }
}

TEST(TestModuleGrouped, BasePrecedenceMultipleGroupsMonitoringMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id2", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 2);
        EXPECT_TRUE(contains(results, "id1"));
        EXPECT_TRUE(contains(results, "id2"));
    }
}

TEST(TestModuleGrouped, BasePrecedenceMultipleGroupsBlockingMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id2", "name", std::move(tags), builder.build()));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id1"));
    }
}

TEST(TestModuleGrouped, MultipleGroupsRulesAndMatches)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.2"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id2", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.2"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id3", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id4", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user, core_rule::verdict_type::block));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.2"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type3"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id5", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.2"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type4"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id6", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type5"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id7", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user, core_rule::verdict_type::block));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type6"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id8", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{user_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    {
        rule_module_cache cache;
        mod.init_cache(cache);

        auto store = object_store::make_context_store();

        auto root = object_builder::map({{"http.client_ip", "192.168.0.2"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 4);
        EXPECT_TRUE(contains(results, "id2"));
        EXPECT_TRUE(contains(results, "id3"));
        EXPECT_TRUE(contains(results, "id5"));
        EXPECT_TRUE(contains(results, "id6"));
    }
}

TEST(TestModuleGrouped, MultipleGroupsSingleMatchPerGroup)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id2", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id3", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id4", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type3"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id5", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    rule_module_builder mod_builder{user_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    {
        rule_module_cache cache;
        mod.init_cache(cache);

        auto store = object_store::make_context_store();

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(results.size(), 3);

        EXPECT_TRUE(contains(results, "id1"));
        EXPECT_TRUE(contains(results, "id3"));
        EXPECT_TRUE(contains(results, "id5"));
    }
}

TEST(TestModuleGrouped, MultipleGroupsOnlyBlockingMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id1", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(
            std::make_shared<core_rule>("id2", "name", std::move(tags), builder.build()));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id3", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user, core_rule::verdict_type::block));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id4", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type3"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id5", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::user));
    }

    rule_module_builder mod_builder{user_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    {
        rule_module_cache cache;
        mod.init_cache(cache);

        auto store = object_store::make_context_store();

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id3"));
    }
}

TEST(TestModuleGrouped, DisabledRules)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<core_rule>("id1", "name", std::move(tags),
            builder.build(), std::vector<std::string>{}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::monitor, false));
    }

    rule_module_builder mod_builder{user_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(results, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::none);
    }
}

TEST(TestModuleGrouped, NonExpiringModule)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<core_rule>("id", "name", std::move(tags), builder.build());

    rule_module_builder mod_builder{
        base_rule_precedence, type_grouping_key, rule_module::expiration_policy::non_expiring};
    mod_builder.insert(rule.get());

    auto mod = mod_builder.build();
    EXPECT_FALSE(mod.may_expire());

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline{0s};
        mod.eval(results, store, cache, {}, {}, deadline);

        EXPECT_EQ(results.size(), 1);
        EXPECT_TRUE(contains(results, "id"));
    }
}

TEST(TestModuleGrouped, ExpiringModule)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<core_rule>("id", "name", std::move(tags), builder.build());

    rule_module_builder mod_builder{
        base_rule_precedence, type_grouping_key, rule_module::expiration_policy::expiring};
    mod_builder.insert(rule.get());

    auto mod = mod_builder.build();
    EXPECT_TRUE(mod.may_expire());

    rule_module_cache cache;
    mod.init_cache(cache);

    auto store = object_store::make_context_store();
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root));

        std::vector<rule_result> results;
        ddwaf::timer deadline{0s};
        EXPECT_THROW(mod.eval(results, store, cache, {}, {}, deadline), ddwaf::timeout_exception);
    }
}

} // namespace
