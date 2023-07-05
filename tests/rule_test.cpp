// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestRule, Match)
{
    expression_builder builder(1);
    builder.start_condition<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};
    ddwaf::rule rule(
        "id", "name", std::move(tags), builder.build(), {"update", "block", "passlist"});

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    rule::cache_type cache;
    auto event = rule.match(store, cache, {}, {}, deadline);
    EXPECT_TRUE(event.has_value());

    EXPECT_STREQ(event->rule->get_id().c_str(), "id");
    EXPECT_STREQ(event->rule->get_name().c_str(), "name");
    EXPECT_STREQ(event->rule->get_tag("type").data(), "type");
    EXPECT_STREQ(event->rule->get_tag("category").data(), "category");
    std::vector<std::string> expected_actions{"update", "block", "passlist"};
    EXPECT_EQ(event->rule->get_actions(), expected_actions);
    EXPECT_EQ(event->matches.size(), 1);

    auto &match = event->matches[0];
    EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
    EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
    EXPECT_STREQ(match.operator_name.data(), "ip_match");
    EXPECT_STREQ(match.operator_value.data(), "");
    EXPECT_STREQ(match.address.data(), "http.client_ip");
    EXPECT_TRUE(match.key_path.empty());
}

TEST(TestRule, NoMatch)
{
    expression_builder builder(1);
    builder.start_condition<rule_processor::ip_match>(std::vector<std::string_view>{});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};
    ddwaf::rule rule("id", "name", std::move(tags), builder.build());

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    rule::cache_type cache;
    auto match = rule.match(store, cache, {}, {}, deadline);
    EXPECT_FALSE(match.has_value());
}

TEST(TestRule, ValidateCachedMatch)
{
    expression_builder builder(2);
    builder.start_condition<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<rule_processor::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule("id", "name", std::move(tags), builder.build());
    ddwaf::rule::cache_type cache;

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto event = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto event = rule.match(store, cache, {}, {}, deadline);
        EXPECT_TRUE(event.has_value());
        EXPECT_STREQ(event->rule->get_id().c_str(), "id");
        EXPECT_STREQ(event->rule->get_name().c_str(), "name");
        EXPECT_STREQ(event->rule->get_tag("type").data(), "type");
        EXPECT_STREQ(event->rule->get_tag("category").data(), "category");
        EXPECT_TRUE(event->rule->get_actions().empty());
        EXPECT_EQ(event->matches.size(), 2);

        {
            auto &match = event->matches[0];
            EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.operator_name.data(), "ip_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.address.data(), "http.client_ip");
            EXPECT_TRUE(match.key_path.empty());
        }
        {
            auto &match = event->matches[1];
            EXPECT_STREQ(match.resolved.c_str(), "admin");
            EXPECT_STREQ(match.matched.c_str(), "admin");
            EXPECT_STREQ(match.operator_name.data(), "exact_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.address.data(), "usr.id");
            EXPECT_TRUE(match.key_path.empty());
        }
    }
}

TEST(TestRule, MatchWithoutCache)
{
    expression_builder builder(2);
    builder.start_condition<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<rule_processor::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule("id", "name", std::move(tags), builder.build());

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    ddwaf::object_store store;
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        ddwaf::rule::cache_type cache;
        auto event = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        ddwaf::rule::cache_type cache;
        auto event = rule.match(store, cache, {}, {}, deadline);
        EXPECT_TRUE(event.has_value());

        {
            auto &match = event->matches[0];
            EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.operator_name.data(), "ip_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.address.data(), "http.client_ip");
            EXPECT_TRUE(match.key_path.empty());
        }
        {
            auto &match = event->matches[1];
            EXPECT_STREQ(match.resolved.c_str(), "admin");
            EXPECT_STREQ(match.matched.c_str(), "admin");
            EXPECT_STREQ(match.operator_name.data(), "exact_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.address.data(), "usr.id");
            EXPECT_TRUE(match.key_path.empty());
        }
    }
}

TEST(TestRule, NoMatchWithoutCache)
{
    expression_builder builder(2);
    builder.start_condition<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<rule_processor::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule("id", "name", std::move(tags), builder.build());

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        ddwaf::rule::cache_type cache;
        auto event = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        ddwaf::rule::cache_type cache;
        auto event = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }
}

TEST(TestRule, FullCachedMatchSecondRun)
{
      expression_builder builder(2);
    builder.start_condition<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<rule_processor::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");
  
    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule("id", "name", std::move(tags), builder.build());

    // In this test we validate that when a match has already occurred, the
    // second run for the same rule returns no events regardless of input.

    ddwaf::rule::cache_type cache;
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto event = rule.match(store, cache, {}, {}, deadline);
        EXPECT_TRUE(event.has_value());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto event = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }
}

TEST(TestRule, ExcludeObject)
{
    expression_builder builder(1);
    builder.start_condition<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule(
        "id", "name", std::move(tags), builder.build(), {"update", "block", "passlist"});

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    rule::cache_type cache;
    auto event = rule.match(store, cache, {&root.array[0]}, {}, deadline);
    EXPECT_FALSE(event.has_value());
}
