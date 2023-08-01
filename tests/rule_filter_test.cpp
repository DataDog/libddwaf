// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestRuleFilter, Match)
{
    expression_builder builder(1);
    builder.start_condition<operation::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    ddwaf::exclusion::rule_filter filter{"filter", builder.build(), {rule.get()}};

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};

    ddwaf::exclusion::rule_filter::cache_type cache;
    EXPECT_FALSE(filter.match(store, cache, deadline)->get().empty());
}

TEST(TestRuleFilter, NoMatch)
{
    expression_builder builder(1);
    builder.start_condition<operation::ip_match>(std::vector<std::string_view>{});
    builder.add_target("http.client_ip");

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
    expression_builder builder(2);

    builder.start_condition<operation::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<operation::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
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
        EXPECT_FALSE(filter.match(store, cache, deadline)->get().empty());
    }
}

TEST(TestRuleFilter, MatchWithoutCache)
{
    expression_builder builder(2);

    builder.start_condition<operation::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<operation::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
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
        EXPECT_FALSE(filter.match(store, cache, deadline)->get().empty());
    }
}

TEST(TestRuleFilter, NoMatchWithoutCache)
{
    expression_builder builder(2);

    builder.start_condition<operation::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<operation::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
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
    expression_builder builder(2);

    builder.start_condition<operation::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<operation::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
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
        EXPECT_FALSE(filter.match(store, cache, deadline)->get().empty());
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
    auto rule = readFile("exclude_one_rule.yaml");
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
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "type2"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .address = "http.client_ip",
                               .value = "192.168.0.1",
                               .highlight = "192.168.0.1"}}});
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByType)
{
    auto rule = readFile("exclude_by_type.yaml");
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
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .address = "http.client_ip",
                               .value = "192.168.0.1",
                               .highlight = "192.168.0.1"}}});
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByCategory)
{
    auto rule = readFile("exclude_by_category.yaml");
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
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_OK);

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByTags)
{
    auto rule = readFile("exclude_by_tags.yaml");
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
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "type2"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .address = "http.client_ip",
                               .value = "192.168.0.1",
                               .highlight = "192.168.0.1"}}});
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeAllWithCondition)
{
    auto rule = readFile("exclude_all_with_condition.yaml");
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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_OK);

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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeSingleRuleWithCondition)
{
    auto rule = readFile("exclude_one_rule_with_condition.yaml");
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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .address = "http.client_ip",
                                   .value = "192.168.0.1",
                                   .highlight = "192.168.0.1"}}});

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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeSingleRuleWithConditionAndTransformers)
{
    auto rule = readFile("exclude_one_rule_with_condition_and_transformers.yaml");
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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .address = "http.client_ip",
                                   .value = "192.168.0.1",
                                   .highlight = "192.168.0.1"}}});

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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}
TEST(TestRuleFilter, ExcludeByTypeWithCondition)
{
    auto rule = readFile("exclude_by_type_with_condition.yaml");
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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .address = "http.client_ip",
                                   .value = "192.168.0.1",
                                   .highlight = "192.168.0.1"}}});

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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByCategoryWithCondition)
{
    auto rule = readFile("exclude_by_category_with_condition.yaml");
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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_OK);

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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, ExcludeByTagsWithCondition)
{
    auto rule = readFile("exclude_by_tags_with_condition.yaml");
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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .address = "http.client_ip",
                                   .value = "192.168.0.1",
                                   .highlight = "192.168.0.1"}}});

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
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, MonitorSingleRule)
{
    auto rule = readFile("monitor_one_rule.yaml");
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
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"monitor"},
                           .matches = {{.op = "ip_match",
                               .address = "http.client_ip",
                               .value = "192.168.0.1",
                               .highlight = "192.168.0.1"}}});
    EXPECT_THAT(out.actions, WithActions({}));
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, AvoidHavingTwoMonitorOnActions)
{
    auto rule = readFile("multiple_monitor_on_match.yaml");
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
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"monitor"},
                           .matches = {{.op = "ip_match",
                               .address = "http.client_ip",
                               .value = "192.168.0.1",
                               .highlight = "192.168.0.1"}}});
    EXPECT_THAT(out.actions, WithActions({}));
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilter, FilterModePrecedence)
{
    auto rule = readFile("monitor_bypass_precedence.yaml");
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

    EXPECT_EQ(ddwaf_run(context, &root, nullptr, LONG_TIME), DDWAF_OK);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
