// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestObjectStore, InsertAndGetObject)
{
    PWManifest manifest;
    manifest.insert("query", PWManifest::ArgDetails("query", PWT_VALUES_ONLY));
    manifest.insert("query++", PWManifest::ArgDetails("query", PWT_VALUES_ONLY));
    manifest.insert("url", PWManifest::ArgDetails("url", PWT_VALUES_ONLY));
    manifest.insert("url++", PWManifest::ArgDetails("url", PWT_VALUES_ONLY));

    object_store store(manifest);

    ddwaf_object root, object, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", ddwaf_object_string(&tmp, "hello"));

    store.insert_object(root);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(manifest.getTargetArgID("query")));
    EXPECT_NE(store.get_object(manifest.getTargetArgID("query")), nullptr);
    EXPECT_NE(store.get_object(manifest.getTargetArgID("query++")), nullptr);
    EXPECT_EQ(store.get_object(manifest.getTargetArgID("url")), nullptr);
    EXPECT_EQ(store.get_object(manifest.getTargetArgID("url++")), nullptr);

    ddwaf_object_free(&root);
}
