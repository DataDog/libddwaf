// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "PWTransformer.h"
#include "test.h"

using namespace ddwaf;
using namespace ddwaf::exclusion;

TEST(TestInputFilter, InputExclusionNoConditions)
{
    auto query = get_target_index("query");

    object_store store;

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", ddwaf_object_string(&tmp, "value"));
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(query, "query", {});
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", {}, {rule.get()}, std::move(obj_filter));

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
    auto query = get_target_index("query");

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
    obj_filter->insert(query, "query", {"params"});
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", {}, {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("http.client_ip");

    std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
    auto cond = std::make_shared<condition>(std::move(targets),
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(client_ip, "client_ip", {});
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("usr.id");

    std::vector<condition::target_type> targets{{client_ip, "usr.id", {}, {PWT_LOWERCASE}}};
    auto cond = std::make_shared<condition>(std::move(targets),
        std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "ADMIN"));

    ddwaf::object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(client_ip, "client_ip", {});
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("http.client_ip");

    std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
    auto cond = std::make_shared<condition>(std::move(targets),
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));

    ddwaf::object_store store;
    store.insert(root);

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(client_ip, "client_ip", {});
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, deadline);
    ASSERT_FALSE(opt_spec.has_value());
}

TEST(TestInputFilter, ObjectExclusionWithCondition)
{
    auto client_ip = get_target_index("http.client_ip");
    auto query = get_target_index("query");

    std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
    auto cond = std::make_shared<condition>(std::move(targets),
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

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
    obj_filter->insert(query, "query", {"params"});

    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("http.client_ip");
    auto query = get_target_index("query");

    std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
    auto cond = std::make_shared<condition>(std::move(targets),
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

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
    obj_filter->insert(query, "query", {"params"});

    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, cache, deadline);
    ASSERT_FALSE(opt_spec.has_value());
}

TEST(TestInputFilter, InputValidateCachedMatch)
{
    auto client_ip = get_target_index("http.client_ip");
    auto usr_id = get_target_index("usr.id");

    std::vector<std::shared_ptr<condition>> conditions;
    {
        std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
        auto cond = std::make_shared<condition>(
            std::move(targets), std::make_unique<rule_processor::ip_match>(
                                    std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<condition::target_type> targets{{usr_id, "usr.id", {}, {}}};
        auto cond = std::make_shared<condition>(std::move(targets),
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(usr_id, "usr.id");
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("http.client_ip");
    auto usr_id = get_target_index("usr.id");

    std::vector<std::shared_ptr<condition>> conditions;
    {
        std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
        auto cond = std::make_shared<condition>(
            std::move(targets), std::make_unique<rule_processor::ip_match>(
                                    std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<condition::target_type> targets{{usr_id, "usr.id", {}, {}}};
        auto cond = std::make_shared<condition>(std::move(targets),
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(client_ip, "client_ip");
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("http.client_ip");
    auto usr_id = get_target_index("usr.id");

    std::vector<std::shared_ptr<condition>> conditions;
    {
        std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
        auto cond = std::make_shared<condition>(
            std::move(targets), std::make_unique<rule_processor::ip_match>(
                                    std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<condition::target_type> targets{{usr_id, "usr.id", {}, {}}};
        auto cond = std::make_shared<condition>(std::move(targets),
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(client_ip, "client_ip");
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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

        auto [client_ip_ptr, attr] = store.get_target(client_ip);

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
    auto client_ip = get_target_index("http.client_ip");
    auto usr_id = get_target_index("usr.id");

    std::vector<std::shared_ptr<condition>> conditions;
    {
        std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
        auto cond = std::make_shared<condition>(
            std::move(targets), std::make_unique<rule_processor::ip_match>(
                                    std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<condition::target_type> targets{{usr_id, "usr.id", {}, {}}};
        auto cond = std::make_shared<condition>(std::move(targets),
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(client_ip, "client_ip");
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("http.client_ip");
    auto usr_id = get_target_index("usr.id");
    auto query = get_target_index("query");

    std::vector<std::shared_ptr<condition>> conditions;
    {
        std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
        auto cond = std::make_shared<condition>(
            std::move(targets), std::make_unique<rule_processor::ip_match>(
                                    std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<condition::target_type> targets{{usr_id, "usr.id", {}, {}}};
        auto cond = std::make_shared<condition>(std::move(targets),
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(query, "query", {"params"});
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("http.client_ip");
    auto usr_id = get_target_index("usr.id");
    auto query = get_target_index("query");

    std::vector<std::shared_ptr<condition>> conditions;
    {
        std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
        auto cond = std::make_shared<condition>(
            std::move(targets), std::make_unique<rule_processor::ip_match>(
                                    std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<condition::target_type> targets{{usr_id, "usr.id", {}, {}}};
        auto cond = std::make_shared<condition>(std::move(targets),
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(query, "query", {"params"});
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("http.client_ip");
    auto usr_id = get_target_index("usr.id");
    auto query = get_target_index("query");

    std::vector<std::shared_ptr<condition>> conditions;
    {
        std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
        auto cond = std::make_shared<condition>(
            std::move(targets), std::make_unique<rule_processor::ip_match>(
                                    std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<condition::target_type> targets{{usr_id, "usr.id", {}, {}}};
        auto cond = std::make_shared<condition>(std::move(targets),
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(query, "query", {"params"});
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
    auto client_ip = get_target_index("http.client_ip");
    auto usr_id = get_target_index("usr.id");
    auto query = get_target_index("query");

    std::vector<std::shared_ptr<condition>> conditions;
    {
        std::vector<condition::target_type> targets{{client_ip, "http.client_ip", {}, {}}};
        auto cond = std::make_shared<condition>(
            std::move(targets), std::make_unique<rule_processor::ip_match>(
                                    std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<condition::target_type> targets{{usr_id, "usr.id", {}, {}}};
        auto cond = std::make_shared<condition>(std::move(targets),
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(query, "query", {"params"});
    auto rule = std::make_shared<ddwaf::rule>(ddwaf::rule("", "", {}, {}));
    input_filter filter("filter", std::move(conditions), {rule.get()}, std::move(obj_filter));

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
