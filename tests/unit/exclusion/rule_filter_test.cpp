// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "exclusion/rule_filter.hpp"
#include "expression.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestRuleFilter, Match)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    std::unordered_map<target_index, std::string> addresses;
    filter.get_addresses(addresses);
    EXPECT_EQ(addresses.size(), 1);
    EXPECT_STREQ(addresses.begin()->second.c_str(), "http.client_ip");

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    ddwaf::object_store store;
    store.insert(std::move(root), evaluation_scope::context());

    ddwaf::timer deadline{2s};

    exclusion::rule_filter::excluded_set default_set{{}, {}, {}, {}};

    ddwaf::exclusion::rule_filter::cache_type cache;
    auto res = filter.match(store, cache, {}, {}, deadline);
    EXPECT_FALSE(res.value_or(default_set).rules.empty());
    EXPECT_TRUE(res.value_or(default_set).scope.is_context());
    EXPECT_EQ(res.value_or(default_set).mode, exclusion::filter_mode::bypass);
}

TEST(TestRuleFilter, MatchWithDynamicMatcher)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition_with_data<matcher::ip_match>("ip_data");

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    std::unordered_map<target_index, std::string> addresses;
    filter.get_addresses(addresses);
    EXPECT_EQ(addresses.size(), 1);
    EXPECT_STREQ(addresses.begin()->second.c_str(), "http.client_ip");

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        ddwaf::object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};

        ddwaf::exclusion::rule_filter::cache_type cache;
        auto res = filter.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(res.has_value());
    }

    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        ddwaf::object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};

        std::unordered_map<std::string, std::unique_ptr<matcher::base>> matchers;
        matchers["ip_data"] =
            std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        exclusion::rule_filter::excluded_set default_set{
            .rules = {}, .scope = {}, .mode = {}, .action = {}};

        ddwaf::exclusion::rule_filter::cache_type cache;
        auto res = filter.match(store, cache, matchers, {}, deadline);
        EXPECT_FALSE(res.value_or(default_set).rules.empty());
        EXPECT_TRUE(res.value_or(default_set).scope.is_context());
        EXPECT_EQ(res.value_or(default_set).mode, exclusion::filter_mode::bypass);
    }
}

TEST(TestRuleFilter, SubcontextMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    std::unordered_map<target_index, std::string> addresses;
    filter.get_addresses(addresses);
    EXPECT_EQ(addresses.size(), 1);
    EXPECT_STREQ(addresses.begin()->second.c_str(), "http.client_ip");

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    ddwaf::object_store store;
    store.insert(std::move(root), evaluation_scope::subcontext());

    ddwaf::timer deadline{2s};

    exclusion::rule_filter::excluded_set default_set{{}, evaluation_scope::context(), {}, {}};

    ddwaf::exclusion::rule_filter::cache_type cache;
    auto res = filter.match(store, cache, {}, evaluation_scope::subcontext(), deadline);
    EXPECT_FALSE(res.value_or(default_set).rules.empty());
    EXPECT_TRUE(res.value_or(default_set).scope.is_subcontext());
    EXPECT_EQ(res.value_or(default_set).mode, exclusion::filter_mode::bypass);
}

TEST(TestRuleFilter, NoMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{});

    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {}};

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    ddwaf::object_store store;
    store.insert(std::move(root), evaluation_scope::context());

    ddwaf::timer deadline{2s};

    ddwaf::exclusion::rule_filter::cache_type cache;
    EXPECT_FALSE(filter.match(store, cache, {}, {}, deadline));
}

TEST(TestRuleFilter, ValidateCachedMatch)
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

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    ddwaf::exclusion::rule_filter::cache_type cache;

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        ddwaf::object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, {}, deadline));
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});

        ddwaf::object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};

        exclusion::rule_filter::excluded_set default_set{{}, {}, {}, {}};

        auto res = filter.match(store, cache, {}, {}, deadline);
        EXPECT_FALSE(res.value_or(default_set).rules.empty());
        EXPECT_TRUE(res.value_or(default_set).scope.is_context());
        EXPECT_EQ(res.value_or(default_set).mode, exclusion::filter_mode::bypass);
    }
}

TEST(TestRuleFilter, CachedMatchAndSubcontextMatch)
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

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    ddwaf::exclusion::rule_filter::cache_type cache;

    ddwaf::object_store store;
    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    {
        defer cleanup{[&]() {
            store.clear_last_batch();
            store.clear_subcontext_objects();
        }};

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, {}, deadline));
    }

    {
        defer cleanup{[&]() {
            store.clear_last_batch();
            store.clear_subcontext_objects();
        }};

        auto root = object_builder::map({{"usr.id", "admin"}});

        store.insert(std::move(root), evaluation_scope::subcontext());

        ddwaf::timer deadline{2s};
        exclusion::rule_filter::excluded_set default_set{
            .rules = {}, .scope = evaluation_scope::context(), .mode = {}, .action = {}};

        auto res = filter.match(store, cache, {}, evaluation_scope::subcontext(), deadline);
        EXPECT_FALSE(res.value_or(default_set).rules.empty());
        EXPECT_TRUE(res.value_or(default_set).scope.is_subcontext());
        EXPECT_EQ(res.value_or(default_set).mode, exclusion::filter_mode::bypass);
    }
}

TEST(TestRuleFilter, ValidateSubcontextMatchCache)
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

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    ddwaf::exclusion::rule_filter::cache_type cache;

    ddwaf::object_store store;
    auto scope = evaluation_scope::subcontext();

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    {
        defer cleanup{[&]() {
            store.clear_last_batch();
            store.clear_subcontext_objects();
        }};

        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root), scope);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, scope, deadline));
    }

    {
        defer cleanup{[&]() {
            store.clear_last_batch();
            store.clear_subcontext_objects();
        }};

        scope = evaluation_scope::next_subcontext(scope);

        auto root = object_builder::map({{"usr.id", "admin"}});

        store.insert(std::move(root), scope);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, scope, deadline));
    }
}

TEST(TestRuleFilter, MatchWithoutCache)
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

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    ddwaf::object_store store;
    {
        ddwaf::exclusion::rule_filter::cache_type cache;
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, {}, deadline));
    }

    {
        ddwaf::exclusion::rule_filter::cache_type cache;
        auto root = object_builder::map({{"usr.id", "admin"}});

        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, {}, deadline)->rules.empty());
    }
}

TEST(TestRuleFilter, NoMatchWithoutCache)
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

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        ddwaf::exclusion::rule_filter::cache_type cache;
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        ddwaf::object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, {}, deadline));
    }

    {
        ddwaf::exclusion::rule_filter::cache_type cache;
        auto root = object_builder::map({{"usr.id", "admin"}});

        ddwaf::object_store store;
        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, {}, deadline));
    }
}

TEST(TestRuleFilter, FullCachedMatchSecondRun)
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

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    ddwaf::object_store store;
    ddwaf::exclusion::rule_filter::cache_type cache;

    // In this test we validate that when a match has already occurred, the
    // second run for the same filter returns nothing.
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}});

        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, {}, deadline)->rules.empty());
        EXPECT_TRUE(cache.result);
    }

    {
        auto root = object_builder::map({{"random", "random"}});

        store.insert(std::move(root), evaluation_scope::context());

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, {}, deadline));
    }
}

} // namespace
