// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "PWTransformer.h"
#include "test.h"

using namespace ddwaf;

TEST(TestCondition, Match)
{
    std::vector<ddwaf::condition::target_type> targets;

    targets.push_back({get_target_index("server.request.query"), "server.request.query"});

    auto cond = std::make_shared<condition>(
        std::move(targets), std::make_unique<rule_processor::regex_match>(".*", 0, true));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, {}, true, {}, deadline);
    EXPECT_TRUE(match.has_value());

    EXPECT_STREQ(match->resolved.c_str(), "value");
    EXPECT_STREQ(match->matched.c_str(), "value");
    EXPECT_STREQ(match->operator_name.data(), "match_regex");
    EXPECT_STREQ(match->operator_value.data(), ".*");
    EXPECT_STREQ(match->address.data(), "server.request.query");
    EXPECT_TRUE(match->key_path.empty());
}

TEST(TestCondition, MatchWithKeyPath)
{
    std::vector<ddwaf::condition::target_type> targets;

    targets.push_back(
        {get_target_index("server.request.query"), "server.request.query", {"key"}, {}});

    auto cond = std::make_shared<condition>(
        std::move(targets), std::make_unique<rule_processor::regex_match>(".*", 0, true));

    ddwaf_object root;
    ddwaf_object submap;
    ddwaf_object tmp;
    ddwaf_object_map(&submap);
    ddwaf_object_map_add(&submap, "key", ddwaf_object_string(&tmp, "value"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", &submap);

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, {}, true, {}, deadline);
    EXPECT_TRUE(match.has_value());

    EXPECT_STREQ(match->resolved.c_str(), "value");
    EXPECT_STREQ(match->matched.c_str(), "value");
    EXPECT_STREQ(match->operator_name.data(), "match_regex");
    EXPECT_STREQ(match->operator_value.data(), ".*");
    EXPECT_STREQ(match->address.data(), "server.request.query");
    EXPECT_EQ(match->key_path.size(), 1);
    EXPECT_STREQ(match->key_path[0].data(), "key");
}

TEST(TestCondition, MatchWithTransformer)
{
    std::vector<ddwaf::condition::target_type> targets;

    targets.push_back(
        {get_target_index("server.request.query"), "server.request.query", {}, {PWT_LOWERCASE}});

    auto cond = std::make_shared<condition>(
        std::move(targets), std::make_unique<rule_processor::regex_match>("value", 0, true));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "VALUE"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, {}, true, {}, deadline);
    EXPECT_TRUE(match.has_value());

    EXPECT_STREQ(match->resolved.c_str(), "value");
    EXPECT_STREQ(match->matched.c_str(), "value");
    EXPECT_STREQ(match->operator_name.data(), "match_regex");
    EXPECT_STREQ(match->operator_value.data(), "value");
    EXPECT_STREQ(match->address.data(), "server.request.query");
    EXPECT_TRUE(match->key_path.empty());
}

TEST(TestCondition, MatchWithMultipleTransformers)
{
    std::vector<ddwaf::condition::target_type> targets;

    targets.push_back({get_target_index("server.request.query"), "server.request.query", {},
        {PWT_COMPRESS_WHITE, PWT_LOWERCASE}});

    auto cond = std::make_shared<condition>(
        std::move(targets), std::make_unique<rule_processor::regex_match>("^ value $", 0, true));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "    VALUE    "));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, {}, true, {}, deadline);
    EXPECT_TRUE(match.has_value());

    EXPECT_STREQ(match->resolved.c_str(), " value ");
    EXPECT_STREQ(match->matched.c_str(), " value ");
    EXPECT_STREQ(match->operator_name.data(), "match_regex");
    EXPECT_STREQ(match->operator_value.data(), "^ value $");
    EXPECT_STREQ(match->address.data(), "server.request.query");
    EXPECT_TRUE(match->key_path.empty());
}

TEST(TestCondition, MatchOnKeys)
{
    std::vector<ddwaf::condition::target_type> targets;

    targets.push_back({get_target_index("server.request.query"), "server.request.query", {}, {},
        expression::data_source::keys});

    auto cond = std::make_shared<condition>(
        std::move(targets), std::make_unique<rule_processor::regex_match>("value", 0, true));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object value;
    ddwaf_object_map(&value);
    ddwaf_object_map_add(&value, "value", ddwaf_object_string(&tmp, "1729"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", &value);

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, {}, true, {}, deadline);
    EXPECT_TRUE(match.has_value());

    EXPECT_STREQ(match->resolved.c_str(), "value");
    EXPECT_STREQ(match->matched.c_str(), "value");
    EXPECT_STREQ(match->operator_name.data(), "match_regex");
    EXPECT_STREQ(match->operator_value.data(), "value");
    EXPECT_STREQ(match->address.data(), "server.request.query");
    EXPECT_EQ(match->key_path.size(), 1);
    EXPECT_STREQ(match->key_path[0].data(), "value");
}

TEST(TestCondition, MatchOnKeysWithTransformer)
{
    std::vector<ddwaf::condition::target_type> targets;

    targets.push_back({get_target_index("server.request.query"), "server.request.query", {},
        {PWT_LOWERCASE}, expression::data_source::keys});

    auto cond = std::make_shared<condition>(
        std::move(targets), std::make_unique<rule_processor::regex_match>("value", 0, true));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object value;
    ddwaf_object_map(&value);
    ddwaf_object_map_add(&value, "VALUE", ddwaf_object_string(&tmp, "1729"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", &value);

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, {}, true, {}, deadline);
    EXPECT_TRUE(match.has_value());

    EXPECT_STREQ(match->resolved.c_str(), "value");
    EXPECT_STREQ(match->matched.c_str(), "value");
    EXPECT_STREQ(match->operator_name.data(), "match_regex");
    EXPECT_STREQ(match->operator_value.data(), "value");
    EXPECT_STREQ(match->address.data(), "server.request.query");
    EXPECT_EQ(match->key_path.size(), 1);
    EXPECT_STREQ(match->key_path[0].data(), "VALUE");
}

TEST(TestCondition, NoMatch)
{
    std::vector<ddwaf::condition::target_type> targets;

    targets.push_back({get_target_index("http.client_ip"), "http.client_ip"});

    auto cond = std::make_shared<condition>(std::move(targets),
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{}));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, {}, true, {}, deadline);
    EXPECT_FALSE(match.has_value());
}

TEST(TestCondition, ExcludeInput)
{
    std::vector<ddwaf::condition::target_type> targets;

    targets.push_back({get_target_index("server.request.query"), "server.request.query"});

    auto cond = std::make_shared<condition>(
        std::move(targets), std::make_unique<rule_processor::regex_match>(".*", 0, true));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, {&root.array[0]}, true, {}, deadline);
    EXPECT_FALSE(match.has_value());
}

TEST(TestCondition, ExcludeKeyPath)
{
    std::vector<ddwaf::condition::target_type> targets;

    targets.push_back({get_target_index("server.request.query"), "server.request.query"});

    auto cond = std::make_shared<condition>(
        std::move(targets), std::make_unique<rule_processor::regex_match>(".*", 0, true));

    ddwaf_object root;
    ddwaf_object map;
    ddwaf_object tmp;
    ddwaf_object_map(&map);
    ddwaf_object_map_add(&map, "key", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", &map);

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, {&map.array[0]}, true, {}, deadline);
    EXPECT_FALSE(match.has_value());
}
