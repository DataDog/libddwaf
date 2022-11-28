// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;
using namespace ddwaf::exclusion;

TEST(TestObjectFilter, SingleTarget)
{
    ddwaf::manifest_builder mb;
    auto query = mb.insert("query", {});
    auto manifest = mb.build_manifest();
    object_store store(manifest);

    ddwaf_object root, child, tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "params", ddwaf_object_string(&tmp, "paramsvalue"));
    ddwaf_object_map_add(&child, "uri", ddwaf_object_string(&tmp, "uri_value"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", &child);

    store.insert(root);

    object_filter filter;
    filter.insert(query, {"params"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, deadline);

    EXPECT_EQ(objects_filtered.size(), 1);
    EXPECT_NE(objects_filtered.find(&child.array[0]), objects_filtered.end());
}

TEST(TestObjectFilter, MultipleTargets)
{
    ddwaf::manifest_builder mb;
    auto query = mb.insert("query", {});
    auto path_params = mb.insert("path_params", {});
    auto manifest = mb.build_manifest();
    object_store store(manifest);

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
    filter.insert(query, {"uri"});
    filter.insert(path_params, {"token", "value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, deadline);

    EXPECT_EQ(objects_filtered.size(), 2);
    EXPECT_NE(objects_filtered.find(&child.array[1]), objects_filtered.end());
    EXPECT_NE(objects_filtered.find(&object.array[0]), objects_filtered.end());
}

TEST(TestObjectFilter, MissingTarget)
{
    ddwaf::manifest_builder mb;
    mb.insert("query", {});
    mb.insert("path_params", {});
    auto status = mb.insert("status", {});
    auto manifest = mb.build_manifest();
    object_store store(manifest);

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
    filter.insert(status, {"value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, deadline);
    EXPECT_EQ(objects_filtered.size(), 0);
}
