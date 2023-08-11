// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.hpp"

#include "exclusion/input_filter.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"

using namespace ddwaf;
using namespace ddwaf::exclusion;
using namespace std::literals;

TEST(TestInputFilter, InputExclusionNoConditions)
{
    object_store store;

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", ddwaf_object_string(&tmp, "value"));
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {});
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter(
        "filter", std::make_shared<expression>(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_NE(opt_spec->objects.find(&root.array[0]), opt_spec->objects.end());
}

TEST(TestInputFilter, ObjectExclusionNoConditions)
{
    object_store store;

    ddwaf_object root;
    ddwaf_object child;
    ddwaf_object tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "param"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);

    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter(
        "filter", std::make_shared<expression>(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_NE(opt_spec->objects.find(&child.array[0]), opt_spec->objects.end());
}

TEST(TestInputFilter, InputExclusionWithCondition)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip", {});
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_NE(opt_spec->objects.find(&root.array[0]), opt_spec->objects.end());
}

TEST(TestInputFilter, InputExclusionWithConditionAndTransformers)
{
    expression_builder builder(1);
    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id", {}, {transformer_id::lowercase});

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "ADMIN"));

    ddwaf::object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("usr.id"), "usr.id", {});
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_NE(opt_spec->objects.find(&root.array[0]), opt_spec->objects.end());
}

TEST(TestInputFilter, InputExclusionFailedCondition)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));

    ddwaf::object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip", {});
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, deadline);
    ASSERT_FALSE(opt_spec.has_value());
}

TEST(TestInputFilter, ObjectExclusionWithCondition)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    ddwaf_object root;
    ddwaf_object child;
    ddwaf_object tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "query", &child);

    ddwaf::object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_NE(opt_spec->objects.find(&child.array[0]), opt_spec->objects.end());
}

TEST(TestInputFilter, ObjectExclusionFailedCondition)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    ddwaf_object root;
    ddwaf_object child;
    ddwaf_object tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));
    ddwaf_object_map_add(&root, "query", &child);

    ddwaf::object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});

    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, deadline);
    ASSERT_FALSE(opt_spec.has_value());
}

TEST(TestInputFilter, InputValidateCachedMatch)
{
    expression_builder builder(2);

    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("usr.id"), "usr.id");
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    input_filter::cache_type cache;
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline).has_value());
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
        EXPECT_NE(opt_spec->objects.find(&root.array[0]), opt_spec->objects.end());
    }
}

TEST(TestInputFilter, InputMatchWithoutCache)
{
    expression_builder builder(2);

    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, deadline).has_value());
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, deadline).has_value());
    }
}

TEST(TestInputFilter, InputNoMatchWithoutCache)
{
    expression_builder builder(2);

    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    ddwaf::object_store store;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, deadline).has_value());
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        auto [client_ip_ptr, attr] = store.get_target(get_target_index("http.client_ip"));

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        auto opt_spec = filter.match(store, cache, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
        EXPECT_NE(opt_spec->objects.find(client_ip_ptr), opt_spec->objects.end());
    }
}

TEST(TestInputFilter, InputCachedMatchSecondRun)
{
    expression_builder builder(2);

    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    ddwaf::object_store store;
    input_filter::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
        EXPECT_NE(opt_spec->objects.find(&root.array[0]), opt_spec->objects.end());
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "random", ddwaf_object_string(&tmp, "random"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        ASSERT_FALSE(filter.match(store, cache, deadline).has_value());
    }
}

TEST(TestInputFilter, ObjectValidateCachedMatch)
{
    expression_builder builder(2);

    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    input_filter::cache_type cache;
    {
        ddwaf_object root;
        ddwaf_object object;
        ddwaf_object tmp;
        ddwaf_object_map(&object);
        ddwaf_object_map_add(&object, "params", ddwaf_object_string(&tmp, "value"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "query", &object);

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        EXPECT_FALSE(filter.match(store, cache, deadline).has_value());
    }

    {
        ddwaf_object root;
        ddwaf_object object;
        ddwaf_object tmp;
        ddwaf_object_map(&object);
        ddwaf_object_map_add(&object, "params", ddwaf_object_string(&tmp, "value"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "query", &object);

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
    }
}

TEST(TestInputFilter, ObjectMatchWithoutCache)
{
    expression_builder builder(2);

    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        ddwaf_object root;
        ddwaf_object object;
        ddwaf_object tmp;
        ddwaf_object_map(&object);
        ddwaf_object_map_add(&object, "params", ddwaf_object_string(&tmp, "value"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "query", &object);

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, deadline).has_value());
    }

    {
        ddwaf_object root;
        ddwaf_object object;
        ddwaf_object tmp;
        ddwaf_object_map(&object);
        ddwaf_object_map_add(&object, "params", ddwaf_object_string(&tmp, "value"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "query", &object);

        ddwaf::object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, deadline).has_value());
    }
}

TEST(TestInputFilter, ObjectNoMatchWithoutCache)
{
    expression_builder builder(2);

    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    ddwaf::object_store store;

    {
        ddwaf_object root;
        ddwaf_object object;
        ddwaf_object tmp;
        ddwaf_object_map(&object);
        ddwaf_object_map_add(&object, "params", ddwaf_object_string(&tmp, "value"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "query", &object);

        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        EXPECT_FALSE(filter.match(store, cache, deadline).has_value());
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        input_filter::cache_type cache;
        auto opt_spec = filter.match(store, cache, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
    }
}

TEST(TestInputFilter, ObjectCachedMatchSecondRun)
{
    expression_builder builder(2);

    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
    builder.add_target("usr.id");

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("query"), "query", {"params"});
    auto rule =
        std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, std::make_shared<expression>()));
    input_filter filter("filter", builder.build(), {rule.get()}, std::move(obj_filter));

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    ddwaf::object_store store;
    input_filter::cache_type cache;

    {
        ddwaf_object root;
        ddwaf_object object;
        ddwaf_object tmp;
        ddwaf_object_map(&object);
        ddwaf_object_map_add(&object, "params", ddwaf_object_string(&tmp, "value"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "query", &object);

        store.insert(root);

        ddwaf::timer deadline{2s};
        auto opt_spec = filter.match(store, cache, deadline);
        ASSERT_TRUE(opt_spec.has_value());
        EXPECT_EQ(opt_spec->rules.size(), 1);
        EXPECT_EQ(opt_spec->objects.size(), 1);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "random", ddwaf_object_string(&tmp, "random"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        ASSERT_FALSE(filter.match(store, cache, deadline).has_value());
    }
}
