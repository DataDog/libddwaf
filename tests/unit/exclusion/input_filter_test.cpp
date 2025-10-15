// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

#include "exclusion/input_filter.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"

using namespace ddwaf;
using namespace std::literals;

TEST(TestInputFilter, InputExclusionNoConditions)
{
    object_store store;

    auto root = object_builder::map({{"query", "value"}});
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter(
        "filter", std::make_shared<expression>(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(root.at(0)));
}

TEST(TestInputFilter, SubcontextInputExclusionNoConditions)
{
    object_store store;

    auto root = object_builder::map({{"query", "value"}});
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter(
        "filter", std::make_shared<expression>(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(root.at(0)));
}

TEST(TestInputFilter, ObjectExclusionNoConditions)
{
    object_store store;

    auto root = object_builder::map();
    auto child = root.emplace("query", object_builder::map());
    child.emplace("params", "param");

    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter(
        "filter", std::make_shared<expression>(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(child.at(0)));
}

TEST(TestInputFilter, SubcontextObjectExclusionNoConditions)
{
    object_store store;

    auto root = object_builder::map();
    auto child = root.emplace("query", object_builder::map());
    child.emplace("params", "param");

    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter(
        "filter", std::make_shared<expression>(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(child.at(0)));
}

TEST(TestInputFilter, PersistentInputExclusionWithPersistentCondition)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
    object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip", {});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(root.at(0)));
}

TEST(TestInputFilter, SubcontextInputExclusionWithSubcontextCondition)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

    object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip", {});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(root.at(0)));
}

TEST(TestInputFilter, PersistentInputExclusionWithSubcontextCondition)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("usr.id");
    builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

    object_store ctx_store;
    auto root = object_builder::map({{"usr.id", "admin"}});
    ctx_store.insert(std::move(root));

    object_store sctx_store{ctx_store};
    root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
    sctx_store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip", {});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(sctx_store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(root.at(0)));
}

TEST(TestInputFilter, SubcontextInputExclusionWithPersistentCondition)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("usr.id");
    builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

    object_store ctx_store;
    auto root = object_builder::map({{"usr.id", "admin"}});
    ctx_store.insert(std::move(root));

    object_store sctx_store{ctx_store};
    root = object_builder::map({{"http.client_ip", "192.168.0.1"}});
    sctx_store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip", {});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(sctx_store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(root.at(0)));
}

TEST(TestInputFilter, InputExclusionWithConditionAndTransformers)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("usr.id", {}, {transformer_id::lowercase});
    builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

    auto root = object_builder::map({{"usr.id", "ADMIN"}});

    object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("usr.id"), "usr.id", {});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(root.at(0)));
}

TEST(TestInputFilter, InputExclusionFailedCondition)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto root = object_builder::map({{"http.client_ip", "192.168.0.2"}});

    object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip", {});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_FALSE(opt_spec.has_value());
}

TEST(TestInputFilter, ObjectExclusionWithCondition)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto root = object_builder::map({
        {"http.client_ip", "192.168.0.1"},
    });

    auto child = root.emplace("query", object_builder::map({{"params", "value"}}));

    object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_TRUE(opt_spec->objects.contains(child.at(0)));
}

TEST(TestInputFilter, ObjectExclusionFailedCondition)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto root = object_builder::map(
        {{"http.client_ip", "192.168.0.2"}, {"query", object_builder::map({{"params", "value"}})}});

    object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});

    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, {}, deadline);
    ASSERT_FALSE(opt_spec.has_value());
}

TEST(TestInputFilter, InputValidateCachedMatch)
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

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("usr.id"), "usr.id");
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    input_filter::cache_type cache;
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, {}, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
        EXPECT_TRUE(opt_spec->objects.contains(root.at(0)));
    }
}

TEST(TestInputFilter, InputValidateCachedSubcontextMatch)
{
    test::expression_builder builder(2);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("usr.id"), "usr.id");
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    std::vector<owned_object> objects;
    objects.emplace_back(object_builder::map({{"http.client_ip", "192.168.0.1"}}));
    objects.emplace_back(object_builder::map({{"usr.id", "admin"}}));
    objects.emplace_back(object_builder::map({{"usr.id", "admin"}}));
    objects.emplace_back(object_builder::map({{"http.client_ip", "192.168.0.1"}}));
    objects.emplace_back(object_builder::map({{"usr.id", "admin"}}));

    input_filter::cache_type ctx_cache;
    object_store ctx_store;

    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};

        ctx_store.insert(objects[1]);

        ddwaf::timer deadline{2s};
        ASSERT_FALSE(filter.match(ctx_store, ctx_cache, {}, deadline));
    }

    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};

        object_store sctx_store{ctx_store};
        sctx_store.insert(objects[0]);

        input_filter::cache_type sctx_cache = ctx_cache;
        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(sctx_store, sctx_cache, {}, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
        EXPECT_TRUE(opt_spec->objects.contains(objects[1].at(0)));
    }

    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};

        ctx_store.insert(objects[2]);

        ddwaf::timer deadline{2s};
        ASSERT_FALSE(filter.match(ctx_store, ctx_cache, {}, deadline));
    }

    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};

        object_store sctx_store{ctx_store};
        sctx_store.insert(objects[3]);

        input_filter::cache_type sctx_cache = ctx_cache;
        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(sctx_store, sctx_cache, {}, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
    }
}

TEST(TestInputFilter, InputMatchWithoutCache)
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

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"}});

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }

    {
        auto root = object_builder::map({{"usr.id", "admin"}});

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }
}

TEST(TestInputFilter, InputNoMatchWithoutCache)
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

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    object_store store;

    std::vector<owned_object> objects;
    objects.emplace_back(object_builder::map({{"http.client_ip", "192.168.0.1"}}));
    objects.emplace_back(object_builder::map({{"usr.id", "admin"}}));

    {
        store.insert(objects[0]);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }

    {
        store.insert(objects[1]);

        auto client_ip_ptr = store.get_target("http.client_ip");

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        auto opt_spec = filter.match(store, cache, {}, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
        EXPECT_TRUE(opt_spec->objects.contains(client_ip_ptr));
    }
}

TEST(TestInputFilter, InputCachedMatchSecondRun)
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

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    object_store store;
    input_filter::cache_type cache;

    std::vector<owned_object> objects;
    objects.emplace_back(
        object_builder::map({{"http.client_ip", "192.168.0.1"}, {"usr.id", "admin"}}));
    objects.emplace_back(object_builder::map({{"random", "random"}}));

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};
        store.insert(objects[0]);

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, {}, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
        EXPECT_TRUE(opt_spec->objects.contains(objects[0].at(0)));
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};
        store.insert(objects[1]);

        ddwaf::timer deadline{2s};
        ASSERT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }
}

TEST(TestInputFilter, ObjectValidateCachedMatch)
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

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    input_filter::cache_type cache;

    std::vector<owned_object> objects;
    objects.emplace_back(object_builder::map({{"http.client_ip", "192.168.0.1"},
        {"query", object_builder::map({{"params", "value"}})}}));
    objects.emplace_back(object_builder::map(
        {{"usr.id", "admin"}, {"query", object_builder::map({{"params", "value"}})}}));

    {
        object_store store;
        store.insert(objects[0]);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }

    {
        object_store store;
        store.insert(objects[1]);

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, {}, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
    }
}

TEST(TestInputFilter, ObjectMatchWithoutCache)
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

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        auto root = object_builder::map({{"http.client_ip", "192.168.0.1"},
            {"query", object_builder::map({{"params", "value"}})}});
        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }

    {

        auto root = object_builder::map(
            {{"usr.id", "admin"}, {"query", object_builder::map({{"params", "value"}})}});
        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }
}

TEST(TestInputFilter, ObjectNoMatchWithoutCache)
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

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    object_store store;

    std::vector<owned_object> objects;
    objects.emplace_back(object_builder::map({{"http.client_ip", "192.168.0.1"},
        {"query", object_builder::map({{"params", "value"}})}}));
    objects.emplace_back(object_builder::map({{"usr.id", "admin"}}));

    {
        store.insert(objects[0]);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }

    {
        store.insert(objects[1]);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        auto opt_spec = filter.match(store, cache, {}, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
    }
}

TEST(TestInputFilter, ObjectCachedMatchSecondRun)
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

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    object_store store;
    input_filter::cache_type cache;

    std::vector<owned_object> objects;
    objects.emplace_back(object_builder::map({{"http.client_ip", "192.168.0.1"},
        {"usr.id", "admin"}, {"query", object_builder::map({{"params", "value"}})}}));
    objects.emplace_back(object_builder::map({{"random", "random"}}));

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};
        store.insert(objects[0]);

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, {}, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};
        store.insert(objects[1]);

        ddwaf::timer deadline{2s};
        ASSERT_FALSE(filter.match(store, cache, {}, deadline).has_value());
    }
}

TEST(TestInputFilter, MatchWithDynamicMatcher)
{
    test::expression_builder builder(2);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition_with_data<matcher::ip_match>("ip_data");

    builder.start_condition();
    builder.add_argument();
    builder.add_target("usr.id");
    builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule = std::make_shared<core_rule>(core_rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    std::vector<owned_object> objects;
    objects.emplace_back(object_builder::map({{"http.client_ip", "192.168.0.1"},
        {"usr.id", "admin"}, {"query", object_builder::map({{"params", "value"}})}}));
    objects.emplace_back(object_builder::map({{"http.client_ip", "192.168.0.1"},
        {"usr.id", "admin"}, {"query", object_builder::map({{"params", "value"}})}}));

    {
        object_store store;
        input_filter::cache_type cache;

        store.insert(objects[0]);

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, {}, deadline);
        ASSERT_FALSE(opt_spec.has_value());
    }

    {
        object_store store;
        input_filter::cache_type cache;

        store.insert(objects[1]);

        std::unordered_map<std::string, std::unique_ptr<matcher::base>> matchers;
        matchers["ip_data"] =
            std::make_unique<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, matchers, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
    }
}
