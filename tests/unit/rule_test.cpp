// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

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

    auto root = object_builder::map();
    root.emplace("http.client_ip", "192.168.0.1");

    ddwaf::object_store store;

    ddwaf::timer deadline{2s};

    core_rule::cache_type cache;
    {
        defer cleanup{[&]() { store.clear_subcontext_objects(); }};
        store.insert(root.clone(), evaluation_scope::context());

        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        ASSERT_TRUE(result.has_value());
        ASSERT_TRUE(result->event.has_value());

        auto &event = result->event.value();
        EXPECT_STR(event.rule.id, "id");
        EXPECT_STR(event.rule.name, "name");
        EXPECT_STR(event.rule.tags.get().at("type"), "type");
        std::vector<std::string> expected_actions{"update", "block", "passlist"};
        EXPECT_EQ(result->actions.get(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);
        EXPECT_TRUE(result->scope.is_context());

        auto &match = event.matches[0];
        EXPECT_STR(match.args[0].resolved, "192.168.0.1");
        EXPECT_STR(match.highlights[0], "192.168.0.1");
        EXPECT_STR(match.operator_name, "ip_match");
        EXPECT_STR(match.operator_value, "");
        EXPECT_STR(match.args[0].address, "http.client_ip");
        EXPECT_TRUE(match.args[0].key_path.empty());
        EXPECT_TRUE(match.scope.is_context());
    }

    {
        defer cleanup{[&]() { store.clear_subcontext_objects(); }};
        store.insert(std::move(root), evaluation_scope::context());

        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(result.has_value());
    }

    EXPECT_TRUE(cache.expr_cache.result);
}

TEST(TestRule, SubcontextMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};
    core_rule rule("id", "name", std::move(tags), builder.build(), {"update", "block", "passlist"});

    ddwaf::object_store store;

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    ddwaf::timer deadline{2s};

    core_rule::cache_type cache;
    {
        defer cleanup{[&]() {
            store.clear_subcontext_objects();
            core_rule::invalidate_subcontext_cache(cache);
        }};
        store.insert(root.clone(), evaluation_scope::subcontext());

        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->scope.is_subcontext());
    }

    {
        defer cleanup{[&]() {
            store.clear_subcontext_objects();
            core_rule::invalidate_subcontext_cache(cache);
        }};
        store.insert(std::move(root), evaluation_scope::subcontext());

        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->scope.is_subcontext());
    }

    EXPECT_FALSE(cache.expr_cache.result);
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

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    ddwaf::object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};

    core_rule::cache_type cache;
    auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
    EXPECT_FALSE(result.has_value());
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
    core_rule::cache_type cache;

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        ddwaf::object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(result.has_value());
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});

        ddwaf::object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        ASSERT_TRUE(result.has_value());
        ASSERT_TRUE(result->event.has_value());

        auto &event = result->event.value();
        EXPECT_STR(event.rule.id, "id");
        EXPECT_STR(event.rule.name, "name");
        EXPECT_STR(event.rule.tags.get().at("type"), "type");
        EXPECT_EQ(event.matches.size(), 2);

        EXPECT_TRUE(result->actions.get().empty());

        {
            auto &match = event.matches[0];
            EXPECT_STR(match.args[0].resolved, "192.168.0.1");
            EXPECT_STR(match.highlights[0], "192.168.0.1");
            EXPECT_STR(match.operator_name, "ip_match");
            EXPECT_STR(match.operator_value, "");
            EXPECT_STR(match.args[0].address, "http.client_ip");
            EXPECT_TRUE(match.args[0].key_path.empty());
        }
        {
            auto &match = event.matches[1];
            EXPECT_STR(match.args[0].resolved, "admin");
            EXPECT_STR(match.highlights[0], "admin");
            EXPECT_STR(match.operator_name, "exact_match");
            EXPECT_STR(match.operator_value, "");
            EXPECT_STR(match.args[0].address, "usr.id");
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
    ddwaf::object_store store;
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        core_rule::cache_type cache;
        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(result.has_value());
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});

        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        core_rule::cache_type cache;
        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        ASSERT_TRUE(result.has_value());
        ASSERT_TRUE(result->event.has_value());

        auto &event = result->event.value();
        {
            auto &match = event.matches[0];
            EXPECT_STR(match.args[0].resolved, "192.168.0.1");
            EXPECT_STR(match.highlights[0], "192.168.0.1");
            EXPECT_STR(match.operator_name, "ip_match");
            EXPECT_STR(match.operator_value, "");
            EXPECT_STR(match.args[0].address, "http.client_ip");
            EXPECT_TRUE(match.args[0].key_path.empty());
        }
        {
            auto &match = event.matches[1];
            EXPECT_STR(match.args[0].resolved, "admin");
            EXPECT_STR(match.highlights[0], "admin");
            EXPECT_STR(match.operator_name, "exact_match");
            EXPECT_STR(match.operator_value, "");
            EXPECT_STR(match.args[0].address, "usr.id");
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

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        ddwaf::object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        core_rule::cache_type cache;
        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(result.has_value());
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});

        ddwaf::object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        core_rule::cache_type cache;
        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(result.has_value());
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

    core_rule::cache_type cache;
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

        ddwaf::object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        EXPECT_TRUE(result.has_value());
        ASSERT_TRUE(result->event.has_value());
    }

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

        ddwaf::object_store store;
        store.insert(std::move(root));

        ddwaf::timer deadline{2s};
        auto [verdict, result] = rule.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(result.has_value());
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

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
    ddwaf::object_store store;
    store.insert(std::move(root));

    std::unordered_set<object_view> excluded_set{store.get_target("http.client_ip").first};

    ddwaf::timer deadline{2s};

    core_rule::cache_type cache;
    auto [verdict, result] =
        rule.match(store, cache, {.context = excluded_set, .subcontext = {}}, {}, deadline);
    EXPECT_FALSE(result.has_value());
}
} // namespace
