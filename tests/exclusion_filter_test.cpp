// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestExclusionFilter, Match)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf::exclusion_filter filter{std::move(conditions), {}};

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    ddwaf::exclusion_filter::cache_type cache;
    EXPECT_TRUE(filter.match(store, manifest, cache, deadline));
}

TEST(TestExclusionFilter, NoMatch)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf::exclusion_filter filter{std::move(conditions), {}};

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    ddwaf::exclusion_filter::cache_type cache;
    EXPECT_FALSE(filter.match(store, manifest, cache, deadline));
}

TEST(TestExclusionFilter, ValidateCachedMatch)
{
    ddwaf::manifest_builder mb;
    std::vector<std::shared_ptr<condition>> conditions;

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto manifest = mb.build_manifest();
    ddwaf::exclusion_filter filter{std::move(conditions), {}};

    ddwaf::exclusion_filter::cache_type cache;

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, manifest, cache, deadline));
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_TRUE(filter.match(store, manifest, cache, deadline));
    }
}

TEST(TestExclusionFilter, MatchWithoutCache)
{
    ddwaf::manifest_builder mb;
    std::vector<std::shared_ptr<condition>> conditions;

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto manifest = mb.build_manifest();
    ddwaf::exclusion_filter filter{std::move(conditions), {}};

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    ddwaf::object_store store(manifest);
    {
        ddwaf::exclusion_filter::cache_type cache;
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, manifest, cache, deadline));
    }

    {
        ddwaf::exclusion_filter::cache_type cache;
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_TRUE(filter.match(store, manifest, cache, deadline));
    }
}

TEST(TestExclusionFilter, NoMatchWithoutCache)
{
    ddwaf::manifest_builder mb;
    std::vector<std::shared_ptr<condition>> conditions;

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto manifest = mb.build_manifest();
    ddwaf::exclusion_filter filter{std::move(conditions), {}};

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        ddwaf::exclusion_filter::cache_type cache;
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, manifest, cache, deadline));
    }

    {
        ddwaf::exclusion_filter::cache_type cache;
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, manifest, cache, deadline));
    }
}

TEST(TestExclusionFilter, FullCachedMatchSecondRun)
{
    ddwaf::manifest_builder mb;
    std::vector<std::shared_ptr<condition>> conditions;

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto manifest = mb.build_manifest();
    ddwaf::exclusion_filter filter{std::move(conditions), {}};

    ddwaf::object_store store(manifest);
    ddwaf::exclusion_filter::cache_type cache;

    // In this test we validate that when a match has already occurred, the
    // second run for the same rule also returns a match (regardless of input).
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_TRUE(filter.match(store, manifest, cache, deadline));
    }

    {
        ddwaf::exclusion_filter::cache_type cache;
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "random", ddwaf_object_string(&tmp, "random"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_TRUE(filter.match(store, manifest, cache, deadline));
    }
}

TEST(TestExclusionFilter, ExcludeSingleRule)
{
    auto rule = readFile("exclude_one_rule.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .type = "type2",
                           .category = "category",
                           .matches = {{.op = "ip_match",
                               .address = "http.client_ip",
                               .value = "192.168.0.1",
                               .highlight = "192.168.0.1"}}});
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExclusionFilter, ExcludeByType)
{
    auto rule = readFile("exclude_by_type.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .type = "type1",
                           .category = "category",
                           .matches = {{.op = "ip_match",
                               .address = "http.client_ip",
                               .value = "192.168.0.1",
                               .highlight = "192.168.0.1"}}});
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExclusionFilter, ExcludeByCategory)
{
    auto rule = readFile("exclude_by_category.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_OK);

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExclusionFilter, ExcludeByTags)
{
    auto rule = readFile("exclude_by_tags.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .type = "type2",
                           .category = "category",
                           .matches = {{.op = "ip_match",
                               .address = "http.client_ip",
                               .value = "192.168.0.1",
                               .highlight = "192.168.0.1"}}});
    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestExclusionFilter, ExcludeAllWithCondition)
{
    auto rule = readFile("exclude_all_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
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

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .type = "type1",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .type = "type2",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestExclusionFilter, ExcludeSingleRuleWithCondition)
{
    auto rule = readFile("exclude_one_rule_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .type = "type2",
                               .category = "category",
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

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .type = "type1",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .type = "type2",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestExclusionFilter, ExcludeByTypeWithCondition)
{
    auto rule = readFile("exclude_by_type_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .type = "type1",
                               .category = "category",
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

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .type = "type1",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .type = "type2",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestExclusionFilter, ExcludeByCategoryWithCondition)
{
    auto rule = readFile("exclude_by_category_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
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

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .type = "type1",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .type = "type2",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestExclusionFilter, ExcludeByTagsWithCondition)
{
    auto rule = readFile("exclude_by_tags_with_condition.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .type = "type2",
                               .category = "category",
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

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_result out;
        EXPECT_EQ(ddwaf_run(context, &root, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .type = "type1",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}},
            {.id = "2",
                .name = "rule2",
                .type = "type2",
                .category = "category",
                .matches = {{.op = "ip_match",
                    .address = "http.client_ip",
                    .value = "192.168.0.1",
                    .highlight = "192.168.0.1"}}});
        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}
