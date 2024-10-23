// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "exception.hpp"
#include "exclusion/object_filter.hpp"

using namespace ddwaf;
using namespace ddwaf::exclusion;
using namespace std::literals;

namespace {
TEST(TestObjectFilter, RootTarget)
{
    auto query = get_target_index("query");

    object_store store;

    ddwaf_object root, child, tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
    ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);

    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, false, deadline);

    ASSERT_EQ(objects_filtered.size(), 1);
    EXPECT_TRUE(objects_filtered.contains(&root.array[0]));
}

TEST(TestObjectFilter, DuplicateTarget)
{
    auto query = get_target_index("query");

    object_store store;

    object_filter filter;
    filter.insert(query, "query", {});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;

    {
        ddwaf_object root, child, tmp;
        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);
        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);

        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(&root.array[0]));
    }

    {
        ddwaf_object root, child, tmp;
        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);
        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);

        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(&root.array[0]));
    }
}

TEST(TestObjectFilter, DuplicateCachedTarget)
{
    auto query = get_target_index("query");

    object_store store;

    object_filter filter;
    filter.insert(query, "query", {});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;

    ddwaf_object root;
    ddwaf_object child;
    ddwaf_object tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
    ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);
    store.insert(root);

    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(&root.array[0]));
    }

    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, SingleTarget)
{
    auto query = get_target_index("query");

    object_store store;

    ddwaf_object root, child, tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
    ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);

    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {"params"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, false, deadline);

    ASSERT_EQ(objects_filtered.size(), 1);
    EXPECT_TRUE(objects_filtered.contains(&child.array[0]));
}

TEST(TestObjectFilter, DuplicateSingleTarget)
{
    auto query = get_target_index("query");

    object_store store;

    object_filter filter;
    filter.insert(query, "query", {"params"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;

    {
        ddwaf_object root, child, tmp;
        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(&child.array[0]));
    }

    {
        ddwaf_object root, child, tmp;
        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(&child.array[0]));
    }
}

TEST(TestObjectFilter, MultipleTargets)
{
    auto query = get_target_index("query");
    auto path_params = get_target_index("path_params");

    object_store store;

    ddwaf_object root, child, sibling, object, tmp;

    // Query
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
    ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));

    // Path Params
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "value", ddwaf_object_string(&tmp, "naskjdnakjsd"));
    ddwaf_object_map_add(&object, "expiration", ddwaf_object_string(&tmp, "yesterday"));

    ddwaf_object_map(&sibling);
    ddwaf_object_map_add(&sibling, "token", &object);
    ddwaf_object_map_add(&sibling, "username", ddwaf_object_string(&tmp, "Paco"));

    // Root object
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);
    ddwaf_object_map_add(&root, "path_params", &sibling);

    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {"uri"});
    filter.insert(path_params, "path_params", {"token", "value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, false, deadline);

    ASSERT_EQ(objects_filtered.size(), 2);
    EXPECT_TRUE(objects_filtered.contains(&child.array[1]));
    EXPECT_TRUE(objects_filtered.contains(&object.array[0]));
}

TEST(TestObjectFilter, DuplicateMultipleTargets)
{
    auto query = get_target_index("query");
    auto path_params = get_target_index("path_params");

    object_store store;

    ddwaf_object root, child, sibling, object, tmp;

    object_filter filter;
    filter.insert(query, "query", {"uri"});
    filter.insert(path_params, "path_params", {"token", "value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;

    {
        // Query
        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));

        // Path Params
        ddwaf_object_map(&object);
        ddwaf_object_map_add(&object, "value", ddwaf_object_string(&tmp, "naskjdnakjsd"));
        ddwaf_object_map_add(&object, "expiration", ddwaf_object_string(&tmp, "yesterday"));

        ddwaf_object_map(&sibling);
        ddwaf_object_map_add(&sibling, "token", &object);
        ddwaf_object_map_add(&sibling, "username", ddwaf_object_string(&tmp, "Paco"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);
        ddwaf_object_map_add(&root, "path_params", &sibling);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);

        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(&child.array[1]));
        EXPECT_TRUE(objects_filtered.contains(&object.array[0]));
    }

    {
        // Query
        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));

        // Path Params
        ddwaf_object_map(&object);
        ddwaf_object_map_add(&object, "value", ddwaf_object_string(&tmp, "naskjdnakjsd"));
        ddwaf_object_map_add(&object, "expiration", ddwaf_object_string(&tmp, "yesterday"));

        ddwaf_object_map(&sibling);
        ddwaf_object_map_add(&sibling, "token", &object);
        ddwaf_object_map_add(&sibling, "username", ddwaf_object_string(&tmp, "Paco"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);
        ddwaf_object_map_add(&root, "path_params", &sibling);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);

        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(&child.array[1]));
        EXPECT_TRUE(objects_filtered.contains(&object.array[0]));
    }
}

TEST(TestObjectFilter, MissingTarget)
{
    get_target_index("query");
    get_target_index("path_params");
    auto status = get_target_index("status");

    object_store store;

    ddwaf_object root, child, sibling, object, tmp;

    // Query
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
    ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));

    // Path Params
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "value", ddwaf_object_string(&tmp, "naskjdnakjsd"));
    ddwaf_object_map_add(&object, "expiration", ddwaf_object_string(&tmp, "yesterday"));

    ddwaf_object_map(&sibling);
    ddwaf_object_map_add(&sibling, "token", &object);
    ddwaf_object_map_add(&sibling, "username", ddwaf_object_string(&tmp, "Paco"));

    // Root object
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);
    ddwaf_object_map_add(&root, "path_params", &sibling);

    store.insert(root);

    object_filter filter;
    filter.insert(status, "status", {"value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, false, deadline);
    ASSERT_EQ(objects_filtered.size(), 0);
}

TEST(TestObjectFilter, SingleTargetCache)
{
    auto query = get_target_index("query");

    object_store store;

    ddwaf_object root, child, tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
    ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);

    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {"params"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(&child.array[0]));
    }

    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        EXPECT_TRUE(objects_filtered.empty());
    }
}

TEST(TestObjectFilter, MultipleTargetsCache)
{
    auto query = get_target_index("query");
    auto path_params = get_target_index("path_params");

    object_store store;

    object_filter filter;
    filter.insert(query, "query", {"uri"});
    filter.insert(path_params, "path_params", {"token", "value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    {
        ddwaf_object root, child, tmp;
        // Query
        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(&child.array[1]));
    }

    {
        ddwaf_object root, child, object, tmp;

        // Path Params
        ddwaf_object_map(&object);
        ddwaf_object_map_add(&object, "value", ddwaf_object_string(&tmp, "naskjdnakjsd"));
        ddwaf_object_map_add(&object, "expiration", ddwaf_object_string(&tmp, "yesterday"));

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "token", &object);
        ddwaf_object_map_add(&child, "username", ddwaf_object_string(&tmp, "Paco"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "path_params", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(&object.array[0]));
    }

    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        EXPECT_TRUE(objects_filtered.empty());
    }
}

TEST(TestObjectFilter, SingleGlobTarget)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"*"});

    ddwaf::timer deadline{2s};
    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, tmp;
        // Query
        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(&child.array[0]));
        EXPECT_TRUE(objects_filtered.contains(&child.array[1]));
    }

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, grandchild, tmp;
        // Query
        ddwaf_object_map(&grandchild);
        ddwaf_object_map_add(&grandchild, "value", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", &grandchild);
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(&child.array[0]));
        EXPECT_TRUE(objects_filtered.contains(&child.array[1]));
    }

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, tmp;
        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", ddwaf_object_invalid(&tmp));

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, GlobAndKeyTarget)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"*"});
    filter.insert(query, "query", {"uri"});

    ddwaf::timer deadline{2s};
    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, tmp;
        // Query
        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(&child.array[0]));
        EXPECT_TRUE(objects_filtered.contains(&child.array[1]));
    }

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, grandchild, tmp;
        // Query
        ddwaf_object_map(&grandchild);
        ddwaf_object_map_add(&grandchild, "value", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", &grandchild);
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(&child.array[0]));
        EXPECT_TRUE(objects_filtered.contains(&child.array[1]));
    }

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, tmp;
        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", ddwaf_object_invalid(&tmp));

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, MultipleComponentsGlobAndKeyTargets)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"*", "value"});
    filter.insert(query, "query", {"uri", "other"});

    ddwaf::timer deadline{2s};

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, grandchild, grandnephew, tmp;
        // Query
        ddwaf_object_map(&grandchild);
        ddwaf_object_map_add(&grandchild, "other", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&grandnephew);
        ddwaf_object_map_add(&grandnephew, "other", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", &grandchild);
        ddwaf_object_map_add(&child, "uri", &grandnephew);

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(&grandnephew.array[0]));
    }

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, grandchild, grandnephew, tmp;
        // Query
        ddwaf_object_map(&grandchild);
        ddwaf_object_map_add(&grandchild, "value", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&grandnephew);
        ddwaf_object_map_add(&grandnephew, "value", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", &grandchild);
        ddwaf_object_map_add(&child, "uri", &grandnephew);

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(&grandnephew.array[0]));
        EXPECT_TRUE(objects_filtered.contains(&grandchild.array[0]));
    }

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, grandchild, grandnephew, tmp;
        // Query
        ddwaf_object_map(&grandchild);
        ddwaf_object_map_add(&grandchild, "whatever", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&grandnephew);
        ddwaf_object_map_add(&grandnephew, "random", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "value", &grandchild);
        ddwaf_object_map_add(&child, "other", &grandnephew);

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, tmp;

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "value", ddwaf_object_string(&tmp, "value"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, MultipleGlobsTargets)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"*", "*", "*"});

    ddwaf::timer deadline{2s};

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, grandchild, grandnephew, greatgrandchild, greatgrandnephew, tmp;

        ddwaf_object_map(&greatgrandchild);
        ddwaf_object_map_add(&greatgrandchild, "other", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(
            &greatgrandchild, "somethingelse", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&grandchild);
        ddwaf_object_map_add(&grandchild, "something", &greatgrandchild);

        ddwaf_object_map(&greatgrandnephew);
        ddwaf_object_map_add(&greatgrandnephew, "other", ddwaf_object_string(&tmp, "paramsvalue"));
        ddwaf_object_map_add(
            &greatgrandnephew, "somethingelse", ddwaf_object_string(&tmp, "paramsvalue"));

        ddwaf_object_map(&grandnephew);
        ddwaf_object_map_add(&grandnephew, "random", &greatgrandnephew);

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", &grandchild);
        ddwaf_object_map_add(&child, "uri", &grandnephew);

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 4);
        EXPECT_TRUE(objects_filtered.contains(&greatgrandchild.array[0]));
        EXPECT_TRUE(objects_filtered.contains(&greatgrandchild.array[1]));
        EXPECT_TRUE(objects_filtered.contains(&greatgrandnephew.array[0]));
        EXPECT_TRUE(objects_filtered.contains(&greatgrandnephew.array[1]));
    }

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, grandchild, grandnephew, tmp;

        ddwaf_object_map(&grandchild);
        ddwaf_object_map_add(&grandchild, "something", ddwaf_object_string(&tmp, "value"));

        ddwaf_object_map(&grandnephew);
        ddwaf_object_map_add(&grandnephew, "random", ddwaf_object_string(&tmp, "value"));

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", &grandchild);
        ddwaf_object_map_add(&child, "uri", &grandnephew);

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, child, tmp;

        ddwaf_object_map(&child);
        ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "value"));
        ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "value"));

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &child);

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, MultipleComponentsMultipleGlobAndKeyTargets)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"a", "b", "c"});
    filter.insert(query, "query", {"a", "*", "d", "e"});
    filter.insert(query, "query", {"a", "*", "e", "*"});
    filter.insert(query, "query", {"a", "*", "f", "*", "g"});

    // Successful tests
    {
        std::vector<std::pair<std::string, std::string>> tests{
            {"{query: {a: {b: {c: hello}}}}", "c"},
            {"{query: {a: {b: {c: {e: hello}}}}}", "c"},
            {"{query: {a: {b: {d: {e: hello}}}}}", "e"},
            {"{query: {a: {h: {d: {e: hello}}}}}", "e"},
            {"{query: {a: {g: {d: {e: {f: [hello, bye]}}}}}}", "e"},
            {"{query: {a: {n: {e: {f: [hello, bye]}}}}}", "f"},
            {"{query: {a: {n: {e: {x: [hello, bye]}}}}}", "x"},
            {"{query: {a: {n: {e: {x: {f: [hello, bye]}}}}}}", "x"},
            {"{query: {a: {p: {f: {x: {g: [hello, bye]}}}}}}", "g"},
            {"{query: {a: {a: {f: {e: {g: {k: [hello, bye]}}}}}}}", "g"},
        };

        for (auto &[object, result] : tests) {
            object_store store;
            object_filter::cache_type cache;
            ddwaf_object root = yaml_to_object(object);
            store.insert(root);

            ddwaf::timer deadline{2s};
            auto objects_filtered = filter.match(store, cache, false, deadline);
            ASSERT_EQ(objects_filtered.size(), 1);
            EXPECT_STREQ((*objects_filtered.persistent.begin())->parameterName, result.c_str());
        }
    }

    // Failure tests
    {
        std::vector<std::string> tests{
            "{query: [a, b, c, d]}",
            "{query: hello}",
            "{query: {a: hello}}",
            "{query: {a: {b: hello}}}",
            "{query: {a: {b: {e: hello}}}}",
            "{query: {a: {b: [c]}}}",
            "{query: {a: {b: {g: {e: hello}}}}}",
            "{query: {a: {b: {f: {e: {h: hello}}}}}}",
        };

        for (auto &object : tests) {
            object_store store;
            object_filter::cache_type cache;
            ddwaf_object root = yaml_to_object(object);
            store.insert(root);

            ddwaf::timer deadline{2s};
            auto objects_filtered = filter.match(store, cache, false, deadline);
            ASSERT_EQ(objects_filtered.size(), 0);
        }
    }
}

TEST(TestObjectFilter, ArrayWithGlobTargets)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"a", "*", "c", "d"});

    {
        object_store store;
        object_filter::cache_type cache;
        ddwaf_object root, a, b, c, d, tmp;

        ddwaf_object_map(&d);
        ddwaf_object_map_add(&d, "d", ddwaf_object_string(&tmp, "value"));

        ddwaf_object_map(&c);
        ddwaf_object_map_add(&c, "c", &d);

        ddwaf_object_array(&b);
        ddwaf_object_array_add(&b, &c);

        ddwaf_object_map(&a);
        ddwaf_object_map_add(&a, "a", &b);

        // Root object
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", &a);

        store.insert(root);

        ddwaf::timer deadline{2s};
        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
    }
}

TEST(TestObjectFilter, Timeout)
{
    auto query = get_target_index("query");

    object_store store;

    ddwaf_object root;
    ddwaf_object child;
    ddwaf_object tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
    ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);

    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {});

    ddwaf::timer deadline{0s};
    object_filter::cache_type cache;
    EXPECT_THROW(filter.match(store, cache, false, deadline), ddwaf::timeout_exception);
}

} // namespace
