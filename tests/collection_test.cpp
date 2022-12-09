// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

// Validate that a rule within the collection matches only once
TEST(TestCollection, SingleRuleMatch)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));
    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    auto rule = std::make_shared<ddwaf::rule>(
        "id", "name", "type", "category", std::move(conditions), std::vector<std::string>{});

    ddwaf::collection rule_collection;
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
        rule_collection.match(events, store, manifest, cache, {}, {}, deadline);

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
        rule_collection.match(events, store, manifest, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that once there's a match for a collection, a second match isn't possible
TEST(TestCollection, MultipleRuleCachedMatch)
{
    ddwaf::collection rule_collection;
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", "type", "category1", std::move(conditions), std::vector<std::string>{});

        rule_collection.insert(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", "type", "category2", std::move(conditions), std::vector<std::string>{});

        rule_collection.insert(rule);
    }

    auto manifest = mb.build_manifest();

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
        rule_collection.match(events, store, manifest, cache, {}, {}, deadline);

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
        rule_collection.match(events, store, manifest, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 0);
    }
}

// Validate that after a failed match, the collection can still produce a match
TEST(TestCollection, MultipleRuleFailAndMatch)
{
    ddwaf::collection rule_collection;
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", "type", "category1", std::move(conditions), std::vector<std::string>{});

        rule_collection.insert(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", "type", "category2", std::move(conditions), std::vector<std::string>{});

        rule_collection.insert(rule);
    }

    auto manifest = mb.build_manifest();

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
        rule_collection.match(events, store, manifest, cache, {}, {}, deadline);

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
        rule_collection.match(events, store, manifest, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }
}

// Validate that the rule cache is acted on
TEST(TestCollection, SingleRuleMultipleCalls)
{
    ddwaf::manifest_builder mb;
    std::vector<condition::ptr> conditions;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        conditions.emplace_back(
            std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
                std::make_unique<rule_processor::ip_match>(
                    std::vector<std::string_view>{"192.168.0.1"})));
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        conditions.emplace_back(
            std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
                std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"})));
    }

    auto manifest = mb.build_manifest();

    auto rule = std::make_shared<ddwaf::rule>(
        "id", "name", "type", "category", std::move(conditions), std::vector<std::string>{});

    ddwaf::collection rule_collection;
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
        rule_collection.match(events, store, manifest, cache, {}, {}, deadline);

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
        rule_collection.match(events, store, manifest, cache, {}, {}, deadline);

        EXPECT_EQ(events.size(), 1);
    }
}
