// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "collection.hpp"
#include "common/gtest_utils.hpp"
#include "condition/scalar_condition.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename T> struct TestCollection : public testing::Test {};

// In the absence of actions, priority collections should behave as regular collections
using CollectionTypes = ::testing::Types<ddwaf::collection, ddwaf::priority_collection>;
TYPED_TEST_SUITE(TestCollection, CollectionTypes);

// Validate that a rule within the collection matches only once
TYPED_TEST(TestCollection, SingleRuleMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<core_rule>("id", "name", std::move(tags), builder.build());

    TypeParam rule_collection;
    rule_collection.insert(rule);

    collection_cache cache;
    ddwaf::object_store store;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);
        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that once there's a match for a collection, a second match isn't possible
TYPED_TEST(TestCollection, MultipleRuleCachedMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    TypeParam rule_collection;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<core_rule>("id1", "name1", std::move(tags), builder.build());

        rules.emplace_back(rule);
        rule_collection.insert(rule);
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<core_rule>("id2", "name2", std::move(tags), builder.build());

        rules.emplace_back(rule);
        rule_collection.insert(rule);
    }

    ddwaf::object_store store;
    collection_cache cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that after a failed match, the collection can still produce a match
TYPED_TEST(TestCollection, MultipleRuleFailAndMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    TypeParam rule_collection;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<core_rule>("id1", "name1", std::move(tags), builder.build());

        rules.emplace_back(rule);
        rule_collection.insert(rule);
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<core_rule>("id2", "name2", std::move(tags), builder.build());

        rules.emplace_back(rule);
        rule_collection.insert(rule);
    }

    ddwaf::object_store store;
    collection_cache cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admino"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }
}

// Validate that the rule cache is acted on
TYPED_TEST(TestCollection, SingleRuleMultipleCalls)
{
    test::expression_builder builder(2);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    builder.start_condition();
    builder.add_argument();
    builder.add_target("usr.id");
    builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<core_rule>("id", "name", std::move(tags), builder.build());

    TypeParam rule_collection;
    rule_collection.insert(rule);

    collection_cache cache;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store;
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }
}

// Validate that a match in a priority collection prevents further regular matches
TEST(TestPriorityCollection, NoRegularMatchAfterPriorityMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    collection regular;
    priority_collection priority;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<core_rule>("id1", "name1", std::move(tags), builder.build());

        rules.emplace_back(rule);
        regular.insert(rule);
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<core_rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"redirect"});

        rules.emplace_back(rule);
        priority.insert(rule);
    }

    ddwaf::object_store store;

    collection_cache cache;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, deadline);

        ASSERT_EQ(events.size(), 1);
        ASSERT_EQ(events[0].rule->get_actions().size(), 1);
        EXPECT_STREQ(events[0].rule->get_actions()[0].data(), "redirect");
    }
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        regular.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that a match in a regular collection doesn't inhibit a match in a
// priority collection
TEST(TestPriorityCollection, PriorityMatchAfterRegularMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    collection regular;
    priority_collection priority;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<core_rule>("id1", "name1", std::move(tags), builder.build());

        rules.emplace_back(rule);
        regular.insert(rule);
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<core_rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"redirect"});

        rules.emplace_back(rule);
        priority.insert(rule);
    }

    ddwaf::object_store store;

    collection_cache cache;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        regular.match(events, store, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
        EXPECT_TRUE(events[0].rule->get_actions().empty());
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, deadline);

        ASSERT_EQ(events.size(), 1);
        ASSERT_EQ(events[0].rule->get_actions().size(), 1);
        EXPECT_STREQ(events[0].rule->get_actions()[0].data(), "redirect");
    }
}

// Validate that a match in a priority collection prevents another match
TEST(TestPriorityCollection, NoPriorityMatchAfterPriorityMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    priority_collection priority;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<core_rule>(
            "id1", "name1", std::move(tags), builder.build(), std::vector<std::string>{"block"});

        rules.emplace_back(rule);
        priority.insert(rule);
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<core_rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"redirect"});

        rules.emplace_back(rule);
        priority.insert(rule);
    }

    ddwaf::object_store store;

    collection_cache cache;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, deadline);

        ASSERT_EQ(events.size(), 1);
        ASSERT_EQ(events[0].rule->get_actions().size(), 1);
        EXPECT_STREQ(events[0].rule->get_actions()[0].data(), "block");
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, deadline);

        ASSERT_EQ(events.size(), 0);
    }
}

// Validate that an ephemeral match in a priority collection doesn't another match
TEST(TestPriorityCollection, NoPriorityMatchAfterEphemeralPriorityMatch)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    priority_collection priority;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<core_rule>(
            "id1", "name1", std::move(tags), builder.build(), std::vector<std::string>{"block"});

        rules.emplace_back(rule);
        priority.insert(rule);
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<core_rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"redirect"});

        rules.emplace_back(rule);
        priority.insert(rule);
    }

    ddwaf::object_store store;

    collection_cache cache;
    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root, object_store::attribute::ephemeral);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, deadline);

        ASSERT_EQ(events.size(), 1);
        ASSERT_EQ(events[0].rule->get_actions().size(), 1);
        EXPECT_STREQ(events[0].rule->get_actions()[0].data(), "block");
    }

    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, deadline);

        ASSERT_EQ(events.size(), 1);
    }
}

// Validate that an ephemeral match in a priority collection prevents another match
// within the same evaluation
TEST(TestPriorityCollection, EphemeralPriorityMatchNoOtherMatches)
{
    std::vector<std::shared_ptr<core_rule>> rules;
    priority_collection priority;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<core_rule>(
            "id1", "name1", std::move(tags), builder.build(), std::vector<std::string>{"block"});

        rules.emplace_back(rule);
        priority.insert(rule);
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<core_rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"redirect"});

        rules.emplace_back(rule);
        priority.insert(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::object_store store;

    collection_cache cache;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root, object_store::attribute::ephemeral);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);
    }

    std::vector<event> events;
    priority.match(events, store, cache, {}, {}, deadline);

    ASSERT_EQ(events.size(), 1);
    ASSERT_EQ(events[0].rule->get_actions().size(), 1);
    EXPECT_STREQ(events[0].rule->get_actions()[0].data(), "block");
}

} // namespace
