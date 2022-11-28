// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;
using namespace ddwaf::exclusion;

TEST(TestInputFilter, InputExclusionNoConditions)
{
    ddwaf::manifest_builder mb;
    auto query = mb.insert("query", {});
    auto manifest = mb.build_manifest();
    object_store store(manifest);

    input_filter filter({}, {std::make_shared<rule>(rule("","", "", "", {}))}, {query});

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, manifest, cache, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->inputs.size(), 1);
    EXPECT_NE(opt_spec->inputs.find(query), opt_spec->inputs.end());
    EXPECT_TRUE(opt_spec->objects.empty());
}

TEST(TestInputFilter, ObjectExclusionNoConditions)
{
    ddwaf::manifest_builder mb;
    auto query = mb.insert("query", {});
    auto manifest = mb.build_manifest();
    object_store store(manifest);

    ddwaf_object root, child, tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "param"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);

    store.insert(root);

    object_filter obj_filter;
    obj_filter.insert(query, {"params"});
    input_filter filter({}, {std::make_shared<rule>(rule("","", "", "", {}))}, {}, obj_filter);

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, manifest, cache, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_TRUE(opt_spec->inputs.empty());
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_NE(opt_spec->objects.find(&child.array[0]), opt_spec->objects.end());
}

TEST(TestInputFilter, InputExclusionWithCondition)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});
    auto manifest = mb.build_manifest();

    std::vector<manifest::target_type> targets{client_ip};
    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    input_filter filter(std::move(conditions), {std::make_shared<rule>(rule("","", "", "", {}))}, {client_ip});

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, manifest, cache, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_EQ(opt_spec->inputs.size(), 1);
    EXPECT_NE(opt_spec->inputs.find(client_ip), opt_spec->inputs.end());
    EXPECT_TRUE(opt_spec->objects.empty());
}

TEST(TestInputFilter, InputExclusionFailedCondition)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});
    auto manifest = mb.build_manifest();

    std::vector<manifest::target_type> targets{client_ip};
    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    input_filter filter(std::move(conditions), {std::make_shared<rule>(rule("","", "", "", {}))}, {client_ip});

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, manifest, cache, deadline);
    ASSERT_FALSE(opt_spec.has_value());
}

TEST(TestInputFilter, ObjectExclusionWithCondition)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});
    auto query = mb.insert("query", {});
    auto manifest = mb.build_manifest();

    std::vector<manifest::target_type> targets{client_ip};
    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf_object root, child, tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "query", &child);

    ddwaf::object_store store(manifest);
    store.insert(root);

    object_filter obj_filter;
    obj_filter.insert(query, {"params"});

    input_filter filter(std::move(conditions), {std::make_shared<rule>(rule("","", "", "", {}))}, {}, obj_filter);

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, manifest, cache, deadline);
    ASSERT_TRUE(opt_spec.has_value());
    EXPECT_EQ(opt_spec->rules.size(), 1);
    EXPECT_TRUE(opt_spec->inputs.empty());
    EXPECT_EQ(opt_spec->objects.size(), 1);
    EXPECT_NE(opt_spec->objects.find(&child.array[0]), opt_spec->objects.end());
}

TEST(TestInputFilter, ObjectExclusionFailedCondition)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});
    auto query = mb.insert("query", {});
    auto manifest = mb.build_manifest();

    std::vector<manifest::target_type> targets{client_ip};
    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf_object root, child, tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));
    ddwaf_object_map_add(&root, "query", &child);

    ddwaf::object_store store(manifest);
    store.insert(root);

    object_filter obj_filter;
    obj_filter.insert(query, {"params"});

    input_filter filter(std::move(conditions), {std::make_shared<rule>(rule("","", "", "", {}))}, {}, obj_filter);

    ddwaf::timer deadline{2s};
    input_filter::cache_type cache;

    auto opt_spec = filter.match(store, manifest, cache, deadline);
    ASSERT_FALSE(opt_spec.has_value());
}


