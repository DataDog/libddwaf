// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "attribute_collector.hpp"
#include "common/gtest_utils.hpp"
#include "expression.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"
#include "object_store.hpp"
#include "rule.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestRule, Match)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};
    core_rule rule("id", "name", std::move(tags), builder.build(), {"update", "block", "passlist"});

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;

    ddwaf::timer deadline{2s};

    attribute_collector collector;
    core_rule::cache_type cache;
    {
        auto scope = store.get_eval_scope();
        store.insert(root, object_store::attribute::none, nullptr);

        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        EXPECT_TRUE(event.has_value());

        EXPECT_STREQ(event->rule->get_id().data(), "id");
        EXPECT_STREQ(event->rule->get_name().data(), "name");
        EXPECT_STREQ(event->rule->get_tag("type").data(), "type");
        EXPECT_STREQ(event->rule->get_tag("category").data(), "category");
        std::vector<std::string> expected_actions{"update", "block", "passlist"};
        EXPECT_EQ(event->rule->get_actions(), expected_actions);
        EXPECT_EQ(event->matches.size(), 1);
        EXPECT_FALSE(event->ephemeral);

        auto &match = event->matches[0];
        EXPECT_STREQ(match.args[0].resolved.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.highlights[0].c_str(), "192.168.0.1");
        EXPECT_STREQ(match.operator_name.data(), "ip_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.args[0].address.data(), "http.client_ip");
        EXPECT_TRUE(match.args[0].key_path.empty());
        EXPECT_FALSE(match.ephemeral);
    }

    {
        auto scope = store.get_eval_scope();
        store.insert(root, object_store::attribute::none, nullptr);

        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }

    EXPECT_TRUE(cache.result);

    ddwaf_object_free(&root);
}

TEST(TestRule, EphemeralMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};
    core_rule rule("id", "name", std::move(tags), builder.build(), {"update", "block", "passlist"});

    ddwaf::object_store store;

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::timer deadline{2s};

    attribute_collector collector;
    core_rule::cache_type cache;
    {
        auto scope = store.get_eval_scope();
        store.insert(root, object_store::attribute::ephemeral, nullptr);

        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        ASSERT_TRUE(event.has_value());
        EXPECT_TRUE(event->ephemeral);
    }

    {
        auto scope = store.get_eval_scope();
        store.insert(root, object_store::attribute::ephemeral, nullptr);

        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        ASSERT_TRUE(event.has_value());
        EXPECT_TRUE(event->ephemeral);
    }

    EXPECT_FALSE(cache.result);

    ddwaf_object_free(&root);
}

TEST(TestRule, NoMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};
    core_rule rule("id", "name", std::move(tags), builder.build());

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    attribute_collector collector;
    core_rule::cache_type cache;
    auto match = rule.match(store, cache, {}, {}, collector, {}, deadline);
    EXPECT_FALSE(match.has_value());
}

TEST(TestRule, ValidateCachedMatch)
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

    core_rule rule("id", "name", std::move(tags), builder.build());

    attribute_collector collector;
    core_rule::cache_type cache;

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
        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
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
        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        EXPECT_TRUE(event.has_value());
        EXPECT_STREQ(event->rule->get_id().data(), "id");
        EXPECT_STREQ(event->rule->get_name().data(), "name");
        EXPECT_STREQ(event->rule->get_tag("type").data(), "type");
        EXPECT_STREQ(event->rule->get_tag("category").data(), "category");
        EXPECT_TRUE(event->rule->get_actions().empty());
        EXPECT_EQ(event->matches.size(), 2);

        {
            auto &match = event->matches[0];
            EXPECT_STREQ(match.args[0].resolved.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.highlights[0].c_str(), "192.168.0.1");
            EXPECT_STREQ(match.operator_name.data(), "ip_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.args[0].address.data(), "http.client_ip");
            EXPECT_TRUE(match.args[0].key_path.empty());
        }
        {
            auto &match = event->matches[1];
            EXPECT_STREQ(match.args[0].resolved.c_str(), "admin");
            EXPECT_STREQ(match.highlights[0].c_str(), "admin");
            EXPECT_STREQ(match.operator_name.data(), "exact_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.args[0].address.data(), "usr.id");
            EXPECT_TRUE(match.args[0].key_path.empty());
        }
    }
}

TEST(TestRule, MatchWithoutCache)
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

    core_rule rule("id", "name", std::move(tags), builder.build());

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    attribute_collector collector;
    ddwaf::object_store store;
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        core_rule::cache_type cache;
        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        core_rule::cache_type cache;
        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        EXPECT_TRUE(event.has_value());

        {
            auto &match = event->matches[0];
            EXPECT_STREQ(match.args[0].resolved.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.highlights[0].c_str(), "192.168.0.1");
            EXPECT_STREQ(match.operator_name.data(), "ip_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.args[0].address.data(), "http.client_ip");
            EXPECT_TRUE(match.args[0].key_path.empty());
        }
        {
            auto &match = event->matches[1];
            EXPECT_STREQ(match.args[0].resolved.c_str(), "admin");
            EXPECT_STREQ(match.highlights[0].c_str(), "admin");
            EXPECT_STREQ(match.operator_name.data(), "exact_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.args[0].address.data(), "usr.id");
            EXPECT_TRUE(match.args[0].key_path.empty());
        }
    }
}

TEST(TestRule, NoMatchWithoutCache)
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

    core_rule rule("id", "name", std::move(tags), builder.build());

    attribute_collector collector;
    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        core_rule::cache_type cache;
        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        core_rule::cache_type cache;
        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }
}

TEST(TestRule, FullCachedMatchSecondRun)
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

    core_rule rule("id", "name", std::move(tags), builder.build());

    // In this test we validate that when a match has already occurred, the
    // second run for the same rule returns no events regardless of input.

    attribute_collector collector;
    core_rule::cache_type cache;
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
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
        auto event = rule.match(store, cache, {}, {}, collector, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }
}

TEST(TestRule, ExcludeObject)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    core_rule rule("id", "name", std::move(tags), builder.build(), {"update", "block", "passlist"});

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    std::unordered_set<const ddwaf_object *> excluded_set{&root.array[0]};
    attribute_collector collector;
    core_rule::cache_type cache;
    auto event = rule.match(
        store, cache, {.persistent = excluded_set, .ephemeral = {}}, {}, collector, {}, deadline);
    EXPECT_FALSE(event.has_value());
}
} // namespace
