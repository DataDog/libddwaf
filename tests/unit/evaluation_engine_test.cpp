// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#include "action_mapper.hpp"
#include "common/gtest_utils.hpp"
#include "context.hpp"
#include "exception.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "expression.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"

#include <gmock/gmock.h>

using namespace ddwaf;
using namespace std::literals;
using namespace ddwaf::exclusion;

namespace {

TEST(TestEvaluationEngine, MatchTimeout)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    ddwaf::timer deadline{0s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    object_store store;
    store.insert(std::move(root));

    std::vector<rule_result> results;
    EXPECT_THROW(engine.eval_rules(store, {}, results, deadline), ddwaf::timeout_exception);
}

TEST(TestEvaluationEngine, NoMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.2"}});

    object_store store;
    store.insert(std::move(root));

    std::vector<rule_result> results;
    engine.eval_rules(store, {}, results, deadline);
    EXPECT_EQ(results.size(), 0);
}

TEST(TestEvaluationEngine, Match)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    object_store store;
    store.insert(std::move(root));

    std::vector<rule_result> results;
    engine.eval_rules(store, {}, results, deadline);
    EXPECT_EQ(results.size(), 1);
}

TEST(TestEvaluationEngine, MatchMultipleRulesInCollectionSingleRun)
{
    test::ruleset_builder rbuilder;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

    object_store store;
    store.insert(std::move(root));

    std::vector<rule_result> results;
    engine.eval_rules(store, {}, results, deadline);
    EXPECT_EQ(results.size(), 1);
    auto result = results[0];
    ASSERT_TRUE(result.event.has_value());

    auto &event = result.event.value();
    EXPECT_STRV(event.rule.id, "id1");
    EXPECT_STRV(event.rule.name, "name1");
    EXPECT_STRV(event.rule.tags.get().at("type"), "type");

    std::vector<std::string> expected_actions{};
    EXPECT_EQ(result.actions.get(), expected_actions);
    EXPECT_EQ(event.matches.size(), 1);

    auto &match = event.matches[0];
    EXPECT_STR(match.args[0].resolved, "192.168.0.1");
    EXPECT_STR(match.highlights[0], "192.168.0.1");
    EXPECT_STRV(match.operator_name, "ip_match");
    EXPECT_STRV(match.operator_value, "");
    EXPECT_STRV(match.args[0].address, "http.client_ip");
    EXPECT_TRUE(match.args[0].key_path.empty());
}

TEST(TestEvaluationEngine, MatchMultipleRulesWithPrioritySingleRun)
{
    test::ruleset_builder rbuilder;
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block});
    }

    auto ruleset = rbuilder.build();
    {
        evaluation_engine engine(ruleset);

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);
        auto result = results[0];
        ASSERT_TRUE(result.event.has_value());

        auto &event = result.event.value();
        EXPECT_STRV(event.rule.id, "id2");
        EXPECT_EQ(result.actions.get().size(), 1);
        EXPECT_STRV(result.actions.get()[0], "block");
    }

    {
        evaluation_engine engine(ruleset);

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

        object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);

        auto result = results[0];
        ASSERT_TRUE(result.event.has_value());

        auto &event = result.event.value();
        EXPECT_STRV(event.rule.id, "id2");
        EXPECT_EQ(result.actions.get().size(), 1);
        EXPECT_STRV(result.actions.get()[0], "block");
    }
}

TEST(TestEvaluationEngine, MatchMultipleRulesInCollectionDoubleRun)
{
    test::ruleset_builder rbuilder;
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());
    object_store store;

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);

        auto result = results[0];
        ASSERT_TRUE(result.event.has_value());

        auto &event = result.event.value();
        EXPECT_STRV(event.rule.id, "id1");
        EXPECT_STRV(event.rule.name, "name1");
        EXPECT_STRV(event.rule.tags.get().at("type"), "type");
        std::vector<std::string> expected_actions{};
        EXPECT_EQ(result.actions.get(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STR(match.args[0].resolved, "192.168.0.1");
        EXPECT_STR(match.highlights[0], "192.168.0.1");
        EXPECT_STRV(match.operator_name, "ip_match");
        EXPECT_STRV(match.operator_value, "");
        EXPECT_STRV(match.args[0].address, "http.client_ip");
        EXPECT_TRUE(match.args[0].key_path.empty());
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }
}

TEST(TestEvaluationEngine, MatchMultipleRulesWithPriorityDoubleRunPriorityLast)
{
    test::ruleset_builder rbuilder;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());
    object_store store;

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);

        auto result = results[0];
        ASSERT_TRUE(result.event.has_value());

        auto &event = result.event.value();
        EXPECT_STRV(event.rule.id, "id1");
        EXPECT_STRV(event.rule.name, "name1");
        EXPECT_STRV(event.rule.tags.get().at("type"), "type");
        std::vector<std::string> expected_actions{};
        EXPECT_EQ(result.actions.get(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STR(match.args[0].resolved, "192.168.0.1");
        EXPECT_STR(match.highlights[0], "192.168.0.1");
        EXPECT_STRV(match.operator_name, "ip_match");
        EXPECT_STRV(match.operator_value, "");
        EXPECT_STRV(match.args[0].address, "http.client_ip");
        EXPECT_TRUE(match.args[0].key_path.empty());
    }

    {
        // An existing match in a collection will not inhibit a match in a
        // priority collection.
        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);

        auto result = results[0];
        ASSERT_TRUE(result.event.has_value());

        auto &event = result.event.value();
        EXPECT_EQ(results.size(), 1);
        EXPECT_STRV(event.rule.id, "id2");
        EXPECT_STRV(event.rule.name, "name2");
        EXPECT_STRV(event.rule.tags.get().at("type"), "type");
        std::vector<std::string> expected_actions{"block"};
        EXPECT_EQ(result.actions.get(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STR(match.args[0].resolved, "admin");
        EXPECT_STR(match.highlights[0], "admin");
        EXPECT_STRV(match.operator_name, "exact_match");
        EXPECT_STRV(match.operator_value, "");
        EXPECT_STRV(match.args[0].address, "usr.id");
        EXPECT_TRUE(match.args[0].key_path.empty());
    }
}

TEST(TestEvaluationEngine, MatchMultipleRulesWithPriorityDoubleRunPriorityFirst)
{
    test::ruleset_builder rbuilder;
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());
    object_store store;

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);

        auto result = results[0];
        ASSERT_TRUE(result.event.has_value());

        auto &event = result.event.value();
        EXPECT_STRV(event.rule.id, "id1");
        EXPECT_STRV(event.rule.name, "name1");
        EXPECT_STRV(event.rule.tags.get().at("type"), "type");
        std::vector<std::string> expected_actions{"block"};
        EXPECT_EQ(result.actions.get(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STR(match.args[0].resolved, "192.168.0.1");
        EXPECT_STR(match.highlights[0], "192.168.0.1");
        EXPECT_STRV(match.operator_name, "ip_match");
        EXPECT_STRV(match.operator_value, "");
        EXPECT_STRV(match.args[0].address, "http.client_ip");
        EXPECT_TRUE(match.args[0].key_path.empty());
    }

    {
        // An existing match in a collection will not inhibit a match in a
        // priority collection.
        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }
}

TEST(TestEvaluationEngine, MatchMultipleCollectionsSingleRun)
{
    test::ruleset_builder rbuilder;
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

    object_store store;
    store.insert(std::move(root));

    std::vector<rule_result> results;
    engine.eval_rules(store, {}, results, deadline);
    EXPECT_EQ(results.size(), 2);
}

TEST(TestEvaluationEngine, MatchPriorityCollectionsSingleRun)
{
    test::ruleset_builder rbuilder;
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build(),
            std::vector<std::string>{"redirect"}});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

    object_store store;
    store.insert(std::move(root));

    std::vector<rule_result> results;
    engine.eval_rules(store, {}, results, deadline);
    EXPECT_EQ(results.size(), 1);
}

TEST(TestEvaluationEngine, MatchMultipleCollectionsDoubleRun)
{
    test::ruleset_builder rbuilder;
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());
    object_store store;

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);
    }

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);
    }
}

TEST(TestEvaluationEngine, MatchMultiplePriorityCollectionsDoubleRun)
{
    test::ruleset_builder rbuilder;
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build(),
            std::vector<std::string>{"redirect"}});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());
    object_store store;

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);
    }

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        std::vector<rule_result> results;
        engine.eval_rules(store, {}, results, deadline);
        EXPECT_EQ(results.size(), 1);
    }
}

TEST(TestEvaluationEngine, RuleFilterWithCondition)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(
            rule_filter{"1", builder.build(), std::set<const core_rule *>{rule}});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

    object_store store;
    store.insert(std::move(root));

    auto rules_to_exclude = engine.eval_filters(store, deadline);
    EXPECT_EQ(rules_to_exclude.size(), 1);
    EXPECT_TRUE(rules_to_exclude.contains(rule));

    std::vector<rule_result> results;
    engine.eval_rules(store, rules_to_exclude, results, deadline);
    EXPECT_EQ(results.size(), 0);
}

TEST(TestEvaluationEngine, RuleFilterWithSubcontextConditionMatch)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(
            rule_filter{"1", builder.build(), std::set<const core_rule *>{rule}});
    }

    evaluation_engine engine(rbuilder.build());

    {
        scope_exit cleanup{[&]() { engine.clear_subcontext_artifacts(); }};

        auto persistent = object_builder::map({{"usr.id", "admin"}});
        auto ephemeral = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        EXPECT_TRUE(engine.insert(std::move(persistent)));
        EXPECT_TRUE(engine.insert(std::move(ephemeral), evaluation_scope::subcontext()));

        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_OK);
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        EXPECT_TRUE(engine.insert(std::move(root)));
        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_MATCH);
    }
}

TEST(TestEvaluationEngine, OverlappingRuleFiltersSubcontextBypassPersistentMonitor)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(
            rule_filter{"1", builder.build(), std::set<const core_rule *>{rule}});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.route");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"unrouted"});

        rbuilder.insert_filter(rule_filter{"2", builder.build(), std::set<const core_rule *>{rule},
            exclusion::filter_mode::monitor});
    }

    evaluation_engine engine(rbuilder.build());

    {
        scope_exit cleanup{[&]() { engine.clear_subcontext_artifacts(); }};

        auto persistent = object_builder::map({{"usr.id", "admin"}, {"http.route", "unrouted"}});
        auto ephemeral = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        EXPECT_TRUE(engine.insert(std::move(persistent)));
        EXPECT_TRUE(engine.insert(std::move(ephemeral), evaluation_scope::subcontext()));

        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_OK);
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        EXPECT_TRUE(engine.insert(std::move(root)));

        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_MATCH);

        EXPECT_TRUE(object_view{res}.find("actions").empty());
    }
}

TEST(TestEvaluationEngine, OverlappingRuleFiltersSubcontextMonitorPersistentBypass)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, std::vector<rule_attribute>{},
            core_rule::source_type::base, core_rule::verdict_type::block});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(), std::set<const core_rule *>{rule},
            exclusion::filter_mode::monitor});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.route");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"unrouted"});

        rbuilder.insert_filter(
            rule_filter{"2", builder.build(), std::set<const core_rule *>{rule}});
    }

    evaluation_engine engine(rbuilder.build());

    {
        scope_exit cleanup{[&]() { engine.clear_subcontext_artifacts(); }};

        auto persistent = object_builder::map({{"usr.id", "admin"}, {"http.route", "unrouted"}});
        auto ephemeral = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        EXPECT_TRUE(engine.insert(std::move(persistent)));
        EXPECT_TRUE(engine.insert(std::move(ephemeral), evaluation_scope::subcontext()));

        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_OK);
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        EXPECT_TRUE(engine.insert(std::move(root)));

        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_OK);
    }
}

TEST(TestEvaluationEngine, RuleFilterTimeout)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(
            rule_filter{"1", builder.build(), std::set<const core_rule *>{rule}});
    }

    ddwaf::timer deadline{0s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"usr.id", "admin"}, {"http.client_ip", "192.168.0.1"}});

    object_store store;
    store.insert(std::move(root));

    EXPECT_THROW(engine.eval_filters(store, deadline), ddwaf::timeout_exception);
}

TEST(TestEvaluationEngine, NoRuleFilterWithCondition)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(
            rule_filter{"1", builder.build(), std::set<const core_rule *>{rule}});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"usr.id", "admin"}, {"http.client_ip", "192.168.0.2"}});

    object_store store;
    store.insert(std::move(root));

    auto rules_to_exclude = engine.eval_filters(store, deadline);
    EXPECT_TRUE(rules_to_exclude.empty());

    std::vector<rule_result> results;
    engine.eval_rules(store, rules_to_exclude, results, deadline);
    EXPECT_EQ(results.size(), 1);
}

TEST(TestEvaluationEngine, MultipleRuleFiltersNonOverlappingRules)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<core_rule *> rules;
    rules.resize(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules[i] = rbuilder.insert_base_rule(core_rule{"id" + std::to_string(i), "name",
            std::move(tags), std::make_shared<expression>(), std::vector<std::string>{}});
    }

    ddwaf::timer deadline{2s};

    {
        evaluation_engine engine(rbuilder.build());
        object_store store;
        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    {
        rbuilder.insert_filter(rule_filter{"1", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[0], rules[1], rules[2]}});
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 3);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
    }

    {
        rbuilder.insert_filter(rule_filter{"2", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[3], rules[4], rules[5]}});
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 6);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
    }

    {
        rbuilder.insert_filter(rule_filter{"3", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[6], rules[7], rules[8]}});
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
    }
}

TEST(TestEvaluationEngine, MultipleRuleFiltersOverlappingRules)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<core_rule *> rules;
    rules.resize(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules[i] = rbuilder.insert_base_rule(core_rule{id, "name", std::move(tags),
            std::make_shared<expression>(), std::vector<std::string>{}});
    }

    ddwaf::timer deadline{2s};

    {
        evaluation_engine engine(rbuilder.build());
        object_store store;
        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    {
        rbuilder.insert_filter(rule_filter{"1", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[0], rules[1], rules[2], rules[3]}});
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 4);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
    }

    {
        rbuilder.insert_filter(rule_filter{"2", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[2], rules[3], rules[4]}});
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 5);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
    }

    {
        rbuilder.insert_filter(rule_filter{"3", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[0], rules[5], rules[6]}});
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 7);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
    }

    {
        rbuilder.insert_filter(rule_filter{"4", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[7], rules[8], rules[6]}});
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
    }

    {
        rbuilder.insert_filter(rule_filter{"5", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[0], rules[1], rules[2], rules[3], rules[4], rules[5],
                rules[6], rules[7], rules[8]}});
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
    }
}

TEST(TestEvaluationEngine, MultipleRuleFiltersNonOverlappingRulesWithConditions)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<core_rule *> rules;
    rules.resize(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules[i] = rbuilder.insert_base_rule(core_rule{std::string(id), "name", std::move(tags),
            std::make_shared<expression>(), std::vector<std::string>{}});
    }
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(),
            std::set<const core_rule *>{rules[0], rules[1], rules[2], rules[3], rules[4]}});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        rbuilder.insert_filter(rule_filter{"2", builder.build(),
            std::set<const core_rule *>{rules[5], rules[6], rules[7], rules[8], rules[9]}});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());
    object_store store;

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(std::move(root));

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 5);
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[9]));
    }

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 10);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[9]));
    }
}

TEST(TestEvaluationEngine, MultipleRuleFiltersOverlappingRulesWithConditions)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<core_rule *> rules;
    rules.resize(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules[i] = rbuilder.insert_base_rule(core_rule{std::string(id), "name", std::move(tags),
            std::make_shared<expression>(), std::vector<std::string>{}});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(),
            std::set<const core_rule *>{
                rules[0], rules[1], rules[2], rules[3], rules[4], rules[5], rules[6]}});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        rbuilder.insert_filter(rule_filter{"2", builder.build(),
            std::set<const core_rule *>{
                rules[3], rules[4], rules[5], rules[6], rules[7], rules[8], rules[9]}});
    }

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());
    object_store store;

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 7);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(std::move(root));

        auto rules_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(rules_to_exclude.size(), 10);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[9]));
    }
}

TEST(TestEvaluationEngine, InputFilterExclude)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

    rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
        std::set<const core_rule *>{rule}, std::move(obj_filter)});

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    object_store store;
    store.insert(std::move(root));

    auto objects_to_exclude = engine.eval_filters(store, deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);

    std::vector<rule_result> results;
    engine.eval_rules(store, objects_to_exclude, results, deadline);
    EXPECT_EQ(results.size(), 0);
}

TEST(TestEvaluationEngine, InputFilterExcludeSubcontext)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.add_target("http.peer_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

    rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
        std::set<const core_rule *>{rule}, std::move(obj_filter)});

    evaluation_engine engine(rbuilder.build());

    {
        scope_exit cleanup{[&]() { engine.clear_subcontext_artifacts(); }};

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        EXPECT_TRUE(engine.insert(std::move(root), evaluation_scope::subcontext()));
        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_OK);
    }

    {
        scope_exit cleanup{[&]() { engine.clear_subcontext_artifacts(); }};

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        EXPECT_TRUE(engine.insert(std::move(root), evaluation_scope::subcontext()));
        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_OK);
    }

    {
        scope_exit cleanup{[&]() { engine.clear_subcontext_artifacts(); }};

        auto root = object_builder::map({{"http.peer_ip", "192.168.0.1"}});
        EXPECT_TRUE(engine.insert(std::move(root), evaluation_scope::subcontext()));
        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_MATCH);
    }
}

// TODO figure out how to test this
/*TEST(TestEvaluationEngine, InputFilterExcludeSubcontextReuseObject)*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("http.client_ip");*/
/*builder.add_target("http.peer_ip");*/
/*builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});*/

/*std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};*/

/*test::ruleset_builder rbuilder{nullptr};*/
/*auto *rule =*/
/*rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});*/

/*auto obj_filter = std::make_shared<object_filter>();*/
/*obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");*/

/*rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),*/
/*std::set<const core_rule *>{rule}, std::move(obj_filter)});*/

/*evaluation_engine engine(rbuilder.build());*/

/*auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});*/
/*    {*/
/*auto [code, res] = engine.eval({}, std::move(root), LONG_TIME);*/
/*EXPECT_EQ(code, DDWAF_OK);*/
/*}*/

/*std::string peer_ip = "http.peer_ip";*/
/*// NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)*/
/*memcpy(const_cast<char *>(root.array[0].parameterName), peer_ip.c_str(), peer_ip.size());*/
/*root.array[0].parameterNameLength = peer_ip.size();*/

/*{*/
/*auto [code, res] = engine.eval({}, std::move(root), LONG_TIME);*/
/*EXPECT_EQ(code, DDWAF_MATCH);*/
/*}*/
/*}*/

TEST(TestEvaluationEngine, InputFilterExcludeRule)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
        std::set<const core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(
        rule_filter{"1", std::make_shared<expression>(), std::set<const core_rule *>{rule}});

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    object_store store;
    store.insert(std::move(root));

    // The rule is added to the filter stage so that it's excluded from the
    // final result, since we're not actually excluding the rule from the match
    // stage we still get an event.
    auto objects_to_exclude = engine.eval_filters(store, deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);

    auto it = objects_to_exclude.context.find(rule);
    it->second.mode = filter_mode::none;
    EXPECT_TRUE(it->second.objects.empty());

    std::vector<rule_result> results;
    engine.eval_rules(store, objects_to_exclude, results, deadline);
    EXPECT_EQ(results.size(), 1);
}

TEST(TestEvaluationEngine, InputFilterExcludeRuleSubcontext)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
        std::set<const core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(
        rule_filter{"1", std::make_shared<expression>(), std::set<const core_rule *>{rule}});

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    object_store store;
    store.insert(std::move(root), evaluation_scope::subcontext());

    auto objects_to_exclude = engine.eval_filters(store, deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);

    auto it = objects_to_exclude.context.find(rule);
    EXPECT_TRUE(it->second.objects.empty());

    EXPECT_FALSE(objects_to_exclude.subcontext.contains(rule));
}

TEST(TestEvaluationEngine, InputFilterMonitorRuleSubcontext)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
        std::set<const core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(rule_filter{"1", std::make_shared<expression>(),
        std::set<const core_rule *>{rule}, filter_mode::monitor});

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    object_store store;
    store.insert(std::move(root), evaluation_scope::subcontext());

    auto policy = engine.eval_filters(store, deadline);
    EXPECT_EQ(policy.size(), 2);

    {
        auto it = policy.context.find(rule);
        EXPECT_TRUE(it->second.objects.empty());
    }

    {
        auto it = policy.subcontext.find(rule);
        EXPECT_FALSE(it->second.objects.empty());
    }
}

TEST(TestEvaluationEngine, InputFilterExcluderRuleSubcontextAndPersistent)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    obj_filter->insert(get_target_index("usr.id"), "usr.id");
    rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
        std::set<const core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(
        rule_filter{"1", std::make_shared<expression>(), std::set<const core_rule *>{rule}});

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());
    object_store store;

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root), evaluation_scope::subcontext());
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(std::move(root));
    }

    auto objects_to_exclude = engine.eval_filters(store, deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);

    auto it = objects_to_exclude.context.find(rule);
    EXPECT_TRUE(it->second.objects.empty());

    EXPECT_FALSE(objects_to_exclude.subcontext.contains(rule));
}

TEST(TestEvaluationEngine, InputFilterMonitorRuleSubcontextAndPersistent)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    obj_filter->insert(get_target_index("usr.id"), "usr.id");
    rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
        std::set<const core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(rule_filter{"1", std::make_shared<expression>(),
        std::set<const core_rule *>{rule}, filter_mode::monitor});

    ddwaf::timer deadline{2s};
    evaluation_engine engine(rbuilder.build());
    object_store store;

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root), evaluation_scope::subcontext());
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(std::move(root));
    }

    auto objects_to_exclude = engine.eval_filters(store, deadline);
    EXPECT_EQ(objects_to_exclude.size(), 2);

    {
        auto it = objects_to_exclude.context.find(rule);
        EXPECT_FALSE(it->second.objects.empty());
    }

    {
        auto it = objects_to_exclude.subcontext.find(rule);
        EXPECT_FALSE(it->second.objects.empty());
    }
}

TEST(TestEvaluationEngine, InputFilterWithCondition)
{
    test::ruleset_builder rbuilder{};

    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<const core_rule *> eval_filters{rule};
        rbuilder.insert_filter(
            input_filter{"1", builder.build(), std::move(eval_filters), std::move(obj_filter)});
    }

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        object_store store;
        store.insert(std::move(root));

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 0);
        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 1);
    }

    // With usr.id != admin, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admino"}});

        object_store store;
        store.insert(std::move(root));

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 0);
        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 1);
    }

    // With usr.id == admin, there should be no matches
    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

        object_store store;
        store.insert(std::move(root));

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 1);
        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }
}

TEST(TestEvaluationEngine, InputFilterWithSubcontextCondition)
{
    test::ruleset_builder rbuilder{};

    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<const core_rule *> eval_filters{rule};
        rbuilder.insert_filter(
            input_filter{"1", builder.build(), std::move(eval_filters), std::move(obj_filter)});
    }

    evaluation_engine engine(rbuilder.build());

    {
        scope_exit cleanup{[&]() { engine.clear_subcontext_artifacts(); }};

        auto persistent = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        auto ephemeral = object_builder::map({{"usr.id", "admin"}});

        EXPECT_TRUE(engine.insert(std::move(persistent)));
        EXPECT_TRUE(engine.insert(std::move(ephemeral), evaluation_scope::subcontext()));
        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_OK);
    }

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        EXPECT_TRUE(engine.insert(std::move(root)));
        timer deadline{std::chrono::microseconds(LONG_TIME)};
        auto [code, res] = engine.eval(deadline);
        EXPECT_EQ(code, DDWAF_MATCH);
    }
}

TEST(TestEvaluationEngine, InputFilterMultipleRules)
{
    test::ruleset_builder rbuilder{};
    std::vector<core_rule *> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        rules.emplace_back(rbuilder.insert_base_rule(
            core_rule{"ip_id", "name", std::move(tags), builder.build()}));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        rules.emplace_back(rbuilder.insert_base_rule(
            core_rule{"usr_id", "name", std::move(tags), builder.build()}));
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
        obj_filter->insert(get_target_index("usr.id"), "usr.id");

        rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[0], rules[1]}, std::move(obj_filter)});
    }

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            EXPECT_EQ(policy.objects.size(), 1);
        }

        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }

    // With usr.id != admin, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admino"}});
        store.insert(std::move(root));

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            EXPECT_EQ(policy.objects.size(), 2);
        }

        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }

    // With usr.id == admin, there should be no matches
    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});
        store.insert(std::move(root));

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            EXPECT_EQ(policy.objects.size(), 2);
        }

        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }
}

TEST(TestEvaluationEngine, InputFilterMultipleRulesMultipleFilters)
{
    test::ruleset_builder rbuilder{};
    std::vector<core_rule *> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        rules.emplace_back(rbuilder.insert_base_rule(
            core_rule{"ip_id", "name", std::move(tags), builder.build()}));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr_id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        rules.emplace_back(rbuilder.insert_base_rule(
            core_rule{"usr_id", "name", std::move(tags), builder.build()}));
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[0]}, std::move(obj_filter)});
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("usr.id"), "usr.id");

        rbuilder.insert_filter(input_filter{"2", std::make_shared<expression>(),
            std::set<const core_rule *>{rules[1]}, std::move(obj_filter)});
    }

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 1);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
        }

        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }

    // With usr.id != admin, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admino"}});
        store.insert(std::move(root));

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
        }

        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }

    // With usr.id == admin, there should be no matches
    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});
        store.insert(std::move(root));

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
        }

        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }
}

TEST(TestEvaluationEngine, InputFilterMultipleRulesMultipleFiltersMultipleObjects)
{
    test::ruleset_builder rbuilder{};

    core_rule *ip_rule;
    core_rule *usr_rule;
    core_rule *cookie_rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        ip_rule =
            rbuilder.insert_base_rule(core_rule{"ip_id", "name", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr_id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        usr_rule = rbuilder.insert_base_rule(
            core_rule{"usr_id", "name", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("server.request.headers", {"cookie"});
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"mycookie"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "cookie_type"}, {"category", "category"}};

        cookie_rule = rbuilder.insert_base_rule(
            core_rule{"cookie_id", "name", std::move(tags), builder.build()});
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
        obj_filter->insert(get_target_index("server.request.headers"), "server.request.headers");

        std::set<const core_rule *> eval_filters{ip_rule, cookie_rule};
        rbuilder.insert_filter(input_filter{
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter)});
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("usr.id"), "usr.id");
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<const core_rule *> eval_filters{usr_rule, ip_rule};
        rbuilder.insert_filter(input_filter{
            "2", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter)});
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("usr.id"), "usr.id");
        obj_filter->insert(get_target_index("server.request.headers"), "server.request.headers");

        std::set<const core_rule *> eval_filters{usr_rule, cookie_rule};
        rbuilder.insert_filter(input_filter{
            "3", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter)});
    }

    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(object_view{root});

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
            EXPECT_TRUE(objects.contains(root.at(0)));
        }

        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map({{"usr.id", "admin"}});
        store.insert(object_view{root});

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
            EXPECT_TRUE(objects.contains(root.at(0)));
        }

        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map(
            {{"server.request.headers", object_builder::map({{"cookie", "mycookie"}})}});
        store.insert(object_view{root});

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
            EXPECT_TRUE(objects.contains(root.at(0)));
        }

        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});
        store.insert(object_view{root});

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 2);
            EXPECT_TRUE(objects.contains(root.at(0)));
            EXPECT_TRUE(objects.contains(root.at(1)));
        }
        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map(
            {{"server.request.headers", object_builder::map({{"cookie", "mycookie"}})},
                {"usr.id", "admin"}});
        store.insert(object_view{root});

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 2);
            EXPECT_TRUE(objects.contains(root.at(0)));
            EXPECT_TRUE(objects.contains(root.at(1)));
        }
        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        evaluation_engine engine(rbuilder.build());
        object_store store;

        auto root = object_builder::map(
            {{"server.request.headers", object_builder::map({{"cookie", "mycookie"}})},
                {"usr.id", "admin"}, {"http.client_ip", "192.168.0.1"}});
        store.insert(object_view{root});

        auto objects_to_exclude = engine.eval_filters(store, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.context) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 3);
            EXPECT_TRUE(objects.contains(root.at(0)));
            EXPECT_TRUE(objects.contains(root.at(1)));
            EXPECT_TRUE(objects.contains(root.at(2)));
        }
        std::vector<rule_result> results;
        engine.eval_rules(store, objects_to_exclude, results, deadline);
        EXPECT_EQ(results.size(), 0);
    }
}

} // namespace
