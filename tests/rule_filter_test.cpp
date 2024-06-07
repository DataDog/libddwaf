// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "exclusion/rule_filter.hpp"
#include "expression.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"
#include "test_utils.hpp"

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

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    std::unordered_map<target_index, std::string> addresses;
    filter.get_addresses(addresses);
    EXPECT_EQ(addresses.size(), 1);
    EXPECT_STREQ(addresses.begin()->second.c_str(), "http.client_ip");

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    exclusion::rule_filter::excluded_set default_set{{}, true, {}};

    ddwaf::exclusion::rule_filter::cache_type cache;
    auto res = filter.match(store, cache, deadline);
    EXPECT_FALSE(res.value_or(default_set).rules.empty());
    EXPECT_FALSE(res.value_or(default_set).ephemeral);
    EXPECT_EQ(res.value_or(default_set).mode, exclusion::filter_mode::bypass);
}

TEST(TestRuleFilter, EphemeralMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    std::unordered_map<target_index, std::string> addresses;
    filter.get_addresses(addresses);
    EXPECT_EQ(addresses.size(), 1);
    EXPECT_STREQ(addresses.begin()->second.c_str(), "http.client_ip");

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root, object_store::attribute::ephemeral);

    ddwaf::timer deadline{2s};

    exclusion::rule_filter::excluded_set default_set{{}, false, {}};

    ddwaf::exclusion::rule_filter::cache_type cache;
    auto res = filter.match(store, cache, deadline);
    EXPECT_FALSE(res.value_or(default_set).rules.empty());
    EXPECT_TRUE(res.value_or(default_set).ephemeral);
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

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    ddwaf::exclusion::rule_filter::cache_type cache;
    EXPECT_FALSE(filter.match(store, cache, deadline));
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

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    ddwaf::exclusion::rule_filter::cache_type cache;

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
        EXPECT_FALSE(filter.match(store, cache, deadline));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};

        exclusion::rule_filter::excluded_set default_set{{}, false, {}};

        auto res = filter.match(store, cache, deadline);
        EXPECT_FALSE(res.value_or(default_set).rules.empty());
        EXPECT_FALSE(res.value_or(default_set).ephemeral);
        EXPECT_EQ(res.value_or(default_set).mode, exclusion::filter_mode::bypass);
    }
}

TEST(TestRuleFilter, CachedMatchAndEphemeralMatch)
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

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    ddwaf::exclusion::rule_filter::cache_type cache;

    ddwaf::object_store store;
    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline));
    }

    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root, object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};
        exclusion::rule_filter::excluded_set default_set{{}, false, {}};

        auto res = filter.match(store, cache, deadline);
        EXPECT_FALSE(res.value_or(default_set).rules.empty());
        EXPECT_TRUE(res.value_or(default_set).ephemeral);
        EXPECT_EQ(res.value_or(default_set).mode, exclusion::filter_mode::bypass);
    }
}

TEST(TestRuleFilter, ValidateEphemeralMatchCache)
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

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    ddwaf::exclusion::rule_filter::cache_type cache;

    ddwaf::object_store store;
    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root, object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline));
    }

    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root, object_store::attribute::ephemeral);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline));
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

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    ddwaf::object_store store;
    {
        ddwaf::exclusion::rule_filter::cache_type cache;
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline));
    }

    {
        ddwaf::exclusion::rule_filter::cache_type cache;
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline)->rules.empty());
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

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        ddwaf::exclusion::rule_filter::cache_type cache;
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline));
    }

    {
        ddwaf::exclusion::rule_filter::cache_type cache;
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline));
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

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    ddwaf::object_store store;
    ddwaf::exclusion::rule_filter::cache_type cache;

    // In this test we validate that when a match has already occurred, the
    // second run for the same filter returns nothing.
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline)->rules.empty());
        EXPECT_TRUE(cache.result);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "random", ddwaf_object_string(&tmp, "random"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline));
    }
}

TEST(TestRuleFilter, ExcludeSingleRule)
{
    auto rule = read_file("exclude_one_rule.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "type2"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1",
                               .args = {{
                                   .value = "192.168.0.1",
                                   .address = "http.client_ip",
                               }}}}});
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByType)
{
    auto rule = read_file("exclude_by_type.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1",
                               .args = {{
                                   .value = "192.168.0.1",
                                   .address = "http.client_ip",
                               }}}}});
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByCategory)
{
    auto rule = read_file("exclude_by_category.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_OK);

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByTags)
{
    auto rule = read_file("exclude_by_tags.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "type2"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1",
                               .args = {{
                                   .value = "192.168.0.1",
                                   .address = "http.client_ip",
                               }}}}});
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeAllWithCondition)
{
    auto rule = read_file("exclude_all_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_OK);

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeSingleRuleWithCondition)
{
    auto rule = read_file("exclude_one_rule_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1",
                                   .args = {{
                                       .value = "192.168.0.1",
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeSingleRuleWithConditionAndTransformers)
{
    auto rule = read_file("exclude_one_rule_with_condition_and_transformers.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "AD      MIN"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1",
                                   .args = {{
                                       .value = "192.168.0.1",
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}
TEST(TestRuleFilter, ExcludeByTypeWithCondition)
{
    auto rule = read_file("exclude_by_type_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1",
                                   .args = {{
                                       .value = "192.168.0.1",
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByCategoryWithCondition)
{
    auto rule = read_file("exclude_by_category_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_OK);

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByTagsWithCondition)
{
    auto rule = read_file("exclude_by_tags_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1",
                                   .args = {{
                                       .value = "192.168.0.1",
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1",
                    .args = {{
                        .value = "192.168.0.1",
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, MonitorSingleRule)
{
    auto rule = read_file("monitor_one_rule.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"monitor"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1",
                               .args = {{
                                   .value = "192.168.0.1",
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, AvoidHavingTwoMonitorOnActions)
{
    auto rule = read_file("multiple_monitor_on_match.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"monitor"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1",
                               .args = {{
                                   .value = "192.168.0.1",
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, MonitorBypassFilterModePrecedence)
{
    auto rule = read_file("monitor_bypass_precedence.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_OK);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, MonitorCustomFilterModePrecedence)
{
    auto rule = read_file("monitor_custom_precedence.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"monitor"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1",
                               .args = {{
                                   .value = "192.168.0.1",
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, BypassCustomFilterModePrecedence)
{
    auto rule = read_file("bypass_custom_precedence.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_OK);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, UnconditionalCustomFilterMode)
{
    auto rule = read_file("exclude_with_custom_action.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"block"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1",
                               .args = {{
                                   .value = "192.168.0.1",
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out,
        {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"}, {"type", "auto"}}}})

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ConditionalCustomFilterMode)
{
    auto rule = read_file("exclude_with_custom_action_and_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .actions = {"block"},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1",
                                   .args = {{
                                       .value = "192.168.0.1",
                                       .address = "http.client_ip",
                                   }}}}});
        EXPECT_ACTIONS(out, {{"block_request", {{"status_code", "403"}, {"grpc_status_code", "10"},
                                                   {"type", "auto"}}}})

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.2",
                                   .args = {{
                                       .value = "192.168.0.2",
                                       .address = "http.client_ip",
                                   }}}}});
        EXPECT_ACTIONS(out, {})

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

} // namespace
