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
    std::unordered_set<std::string_view> seen_actions;
    std::vector<ddwaf::condition::target_type> targets;

    ddwaf::manifest manifest;
    targets.push_back({manifest.insert("http.client_ip"), "http.client_ip", {}});

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>(
        "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

    TypeParam rule_collection;
    rule_collection.insert(rule);

    auto cache = rule_collection.get_cache();
    ddwaf::object_store store(manifest);
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

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
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that once there's a match for a collection, a second match isn't possible
TYPED_TEST(TestCollection, MultipleRuleCachedMatch)
{
    std::unordered_set<std::string_view> seen_actions;
    TypeParam rule_collection;
    ddwaf::manifest manifest;
    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("http.client_ip"), "http.client_ip", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), std::move(conditions), std::vector<std::string>{});

        rule_collection.insert(rule);
    }

    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("usr.id"), "usr.id", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), std::move(conditions), std::vector<std::string>{});

        rule_collection.insert(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::object_store store(manifest);
    auto cache = rule_collection.get_cache();

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

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
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that after a failed match, the collection can still produce a match
TYPED_TEST(TestCollection, MultipleRuleFailAndMatch)
{
    std::unordered_set<std::string_view> seen_actions;
    TypeParam rule_collection;
    ddwaf::manifest manifest;
    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("http.client_ip"), "http.client_ip", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};
        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), std::move(conditions), std::vector<std::string>{});

        rule_collection.insert(rule);
    }

    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("usr.id"), "usr.id", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};
        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), std::move(conditions), std::vector<std::string>{});

        rule_collection.insert(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::object_store store(manifest);
    auto cache = rule_collection.get_cache();

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admino"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

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
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }
}

// Validate that the rule cache is acted on
TYPED_TEST(TestCollection, SingleRuleMultipleCalls)
{
    std::unordered_set<std::string_view> seen_actions;
    ddwaf::manifest manifest;
    std::vector<condition::ptr> conditions;
    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("http.client_ip"), "http.client_ip", {}});

        conditions.emplace_back(
            std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
                std::make_unique<rule_processor::ip_match>(
                    std::vector<std::string_view>{"192.168.0.1"})));
    }

    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("usr.id"), "usr.id", {}});

        conditions.emplace_back(
            std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
                std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"})));
    }

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>(
        "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

    TypeParam rule_collection;
    rule_collection.insert(rule);

    auto cache = rule_collection.get_cache();
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }
}

// Validate that all rules in the priority collection are evaluated in order to
// satisfy the requirement of all actions being fulfilled
TEST(TestPriorityCollection, MatchBothActions)
{
    priority_collection rule_collection;
    ddwaf::manifest manifest;
    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("http.client_ip"), "http.client_ip", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};
        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        rule_collection.insert(rule);
    }

    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("usr.id"), "usr.id", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags),
            std::move(conditions), std::vector<std::string>{"redirect"});

        rule_collection.insert(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::object_store store(manifest);
    std::unordered_set<std::string_view> seen_actions;

    auto cache = rule_collection.get_cache();
    EXPECT_EQ(cache.remaining_actions.size(), 2);
    EXPECT_NE(cache.remaining_actions.find("redirect"), cache.remaining_actions.end());
    EXPECT_NE(cache.remaining_actions.find("block"), cache.remaining_actions.end());

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 2);
        EXPECT_EQ(seen_actions.size(), 2);
        EXPECT_NE(seen_actions.find("redirect"), seen_actions.end());
        EXPECT_NE(seen_actions.find("block"), seen_actions.end());
    }
}

// Validate that once all actions have been seen no other rules are evaluated
TEST(TestPriorityCollection, MatchOneAction)
{
    priority_collection rule_collection;
    ddwaf::manifest manifest;
    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("http.client_ip"), "http.client_ip", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        rule_collection.insert(rule);
    }

    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("usr.id"), "usr.id", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        rule_collection.insert(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::object_store store(manifest);
    std::unordered_set<std::string_view> seen_actions;

    auto cache = rule_collection.get_cache();
    EXPECT_EQ(cache.remaining_actions.size(), 1);
    EXPECT_NE(cache.remaining_actions.find("block"), cache.remaining_actions.end());

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
        EXPECT_EQ(seen_actions.size(), 1);
        EXPECT_NE(seen_actions.find("block"), seen_actions.end());
    }
}

// Validate that (currently) all rules will be evaluated if any action is missing
TEST(TestPriorityCollection, MatchAllIfMissing)
{
    priority_collection rule_collection;
    ddwaf::manifest manifest;
    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("http.client_ip"), "http.client_ip", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        rule_collection.insert(rule);
    }

    {
        std::vector<ddwaf::condition::target_type> targets;
        targets.push_back({manifest.insert("usr.id"), "usr.id", {}});

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        rule_collection.insert(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::object_store store(manifest);
    std::unordered_set<std::string_view> seen_actions;

    // This test can also be done by adding an extra rule that will not match
    // however this hack also works.
    auto cache = rule_collection.get_cache();
    cache.remaining_actions.emplace("redirect");

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        store.insert(root);

        std::vector<event> events;
        ddwaf::timer deadline{2s};
        rule_collection.match(events, seen_actions, store, cache, {}, {}, {}, deadline);

        EXPECT_EQ(events.size(), 2);
        EXPECT_EQ(seen_actions.size(), 1);
        EXPECT_NE(seen_actions.find("block"), seen_actions.end());
    }
}
