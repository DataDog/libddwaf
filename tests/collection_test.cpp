// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

template <typename T> struct TestCollection : public testing::Test {};

// In the absence of actions, priority collections should behave as regular collections
using CollectionTypes = ::testing::Types<ddwaf::collection, ddwaf::priority_collection>;
TYPED_TEST_SUITE(TestCollection, CollectionTypes);

// Validate that a rule within the collection matches only once
TYPED_TEST(TestCollection, SingleRuleMatch)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

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

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);
        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that once there's a match for a collection, a second match isn't possible
TYPED_TEST(TestCollection, MultipleRuleCachedMatch)
{
    std::vector<rule::ptr> rules;
    TypeParam rule_collection;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        rules.emplace_back(rule);
        rule_collection.insert(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags), builder.build());

        rules.emplace_back(rule);
        rule_collection.insert(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::object_store store;
    collection_cache cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that after a failed match, the collection can still produce a match
TYPED_TEST(TestCollection, MultipleRuleFailAndMatch)
{
    std::vector<rule::ptr> rules;
    TypeParam rule_collection;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        rules.emplace_back(rule);
        rule_collection.insert(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags), builder.build());

        rules.emplace_back(rule);
        rule_collection.insert(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::object_store store;
    collection_cache cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admino"));
        store.insert(root);

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }
}

// Validate that the rule cache is acted on
TYPED_TEST(TestCollection, SingleRuleMultipleCalls)
{
    expression_builder builder(2);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

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

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }
}

// Validate that a match in a priority collection prevents further regular matches
TEST(TestPriorityCollection, NoRegularMatchAfterPriorityMatch)
{
    std::vector<rule::ptr> rules;
    collection regular;
    priority_collection priority;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        rules.emplace_back(rule);
        regular.insert(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
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
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, {}, deadline);

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

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        regular.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that a match in a regular collection doesn't inhibit a match in a
// priority collection
TEST(TestPriorityCollection, PriorityMatchAfterRegularMatch)
{
    std::vector<rule::ptr> rules;
    collection regular;
    priority_collection priority;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        rules.emplace_back(rule);
        regular.insert(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
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
        store.insert(root);

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        regular.match(events, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
        EXPECT_TRUE(events[0].rule->get_actions().empty());
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, {}, deadline);

        ASSERT_EQ(events.size(), 1);
        ASSERT_EQ(events[0].rule->get_actions().size(), 1);
        EXPECT_STREQ(events[0].rule->get_actions()[0].data(), "redirect");
    }
}

// Validate that a match in a priority collection prevents another match
TEST(TestPriorityCollection, NoPriorityMatchAfterPriorityMatch)
{
    std::vector<rule::ptr> rules;
    priority_collection priority;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), builder.build(), std::vector<std::string>{"block"});

        rules.emplace_back(rule);
        priority.insert(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
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
        store.insert(root);

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, {}, deadline);

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

        memory::vector<event> events;
        ddwaf::timer deadline{2s};
        priority.match(events, store, cache, {}, {}, {}, deadline);

        ASSERT_EQ(events.size(), 0);
    }
}
