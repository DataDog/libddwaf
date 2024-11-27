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

TEST(TestModule, SingleRuleMatch)
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

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);
        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        mod.eval(events, store, cache, {}, {}, deadline);
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::none);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestModule, MultipleMonitoringRuleMatch)
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

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(events.size(), 2);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);
        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        mod.eval(events, store, cache, {}, {}, deadline);
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::none);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestModule, BlockingRuleMatch)
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
            builder.build(), std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(events.size(), 1);
    }

    // No further calls should happen after a blocking rule matches
}

TEST(TestModule, MonitoringRuleMatch)
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
            builder.build(), std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(events.size(), 1);
    }

    // Check that we can still match the blocking rule
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(events.size(), 1);
    }
}

TEST(TestModule, BlockingRuleMatchBasePrecedence)
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
            builder.build(), std::vector<std::string>{"block"}, true, core_rule::source_type::user,
            core_rule::verdict_type::block));
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
            builder.build(), std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(events.size(), 1);
        EXPECT_STRV(events[0].rule->get_id(), "id2");
    }

    // No further calls should happen after a blocking rule matches
}

TEST(TestModule, BlockingRuleMatchUserPrecedence)
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
            builder.build(), std::vector<std::string>{"block"}, true, core_rule::source_type::user,
            core_rule::verdict_type::block));
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
            builder.build(), std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{user_rule_precedence, null_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(events.size(), 1);
        EXPECT_STRV(events[0].rule->get_id(), "id1");
    }

    // No further calls should happen after a blocking rule matches
}

TEST(TestModule, NonExpiringModule)
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

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{0s};
        mod.eval(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }
}

TEST(TestModule, ExpiringModule)
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

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{0s};
        EXPECT_THROW(mod.eval(events, store, cache, {}, {}, deadline), ddwaf::timeout_exception);
    }
}

TEST(TestModule, MultipleCollectionsMonitoringRuleMatch)
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

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(events.size(), 2);
    }
}

TEST(TestModule, MultipleCollectionsBlockingRuleMatch)
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
            builder.build(), std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(events.size(), 1);
    }
}

TEST(TestModule, SingleCollectionsBlockingRuleMatch)
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
            builder.build(), std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block));
    }

    rule_module_builder mod_builder{base_rule_precedence, type_grouping_key};
    for (const auto &rule : rules) { mod_builder.insert(rule.get()); }

    auto mod = mod_builder.build();

    rule_module_cache cache;
    mod.init_cache(cache);

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::block);
        EXPECT_EQ(events.size(), 1);
    }
}

TEST(TestModule, SingleCollectionsMonitoringRuleMatch)
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

    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline = endless_timer();
        auto verdict = mod.eval(events, store, cache, {}, {}, deadline);
        EXPECT_EQ(verdict, rule_module::verdict_type::monitor);
        EXPECT_EQ(events.size(), 1);
    }
}

} // namespace
