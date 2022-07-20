// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestObjectStore, InsertInvalidObject)
{
    ddwaf::manifest_builder mb;
    auto query = mb.insert("query", {});
    auto query_key= mb.insert("query", {"key"});
    auto url = mb.insert("url", {});
    auto url_key = mb.insert("url", {"key"});
    auto manifest = mb.build_manifest();
    object_store store(manifest);

    ddwaf_object root = DDWAF_OBJECT_INVALID;

    store.insert(root);

    EXPECT_FALSE((bool)store);
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(query_key));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.is_new_target(url_key));
    EXPECT_EQ(store.get_target(query), nullptr);
    EXPECT_EQ(store.get_target(query_key), nullptr);
    EXPECT_EQ(store.get_target(url), nullptr);
    EXPECT_EQ(store.get_target(url_key), nullptr);

    ddwaf_object_free(&root);
}

TEST(TestObjectStore, InsertMalformedMap)
{
    ddwaf::manifest_builder mb;
    auto manifest = mb.build_manifest();

    object_store store(manifest);

    ddwaf_object root = DDWAF_OBJECT_MAP;
    root.nbEntries = 30;

    EXPECT_FALSE(store.insert(root));

    EXPECT_FALSE((bool)store);

    ddwaf_object_free(&root);
}

TEST(TestObjectStore, InsertMalformedMapKey)
{
    ddwaf::manifest_builder mb;
    mb.insert("key", {});
    auto manifest = mb.build_manifest();

    object_store store(manifest);

    ddwaf_object tmp, root = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&root, "key", ddwaf_object_string(&tmp, "value"));

    free((void*)root.array[0].parameterName);
    root.array[0].parameterName = nullptr;

    EXPECT_TRUE(store.insert(root));
    EXPECT_FALSE((bool)store);

    ddwaf_object_free(&root);
}

TEST(TestObjectStore, InsertStringObject)
{
    ddwaf::manifest_builder mb;
    auto query = mb.insert("query", {});
    auto query_key= mb.insert("query", {"key"});
    auto url = mb.insert("url", {});
    auto url_key = mb.insert("url", {"key"});
    auto manifest = mb.build_manifest();

    object_store store(manifest);

    ddwaf_object root;
    ddwaf_object_string(&root, "hello");

    store.insert(root);

    EXPECT_FALSE((bool)store);
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(query_key));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.is_new_target(url_key));
    EXPECT_EQ(store.get_target(query), nullptr);
    EXPECT_EQ(store.get_target(query_key), nullptr);
    EXPECT_EQ(store.get_target(url), nullptr);
    EXPECT_EQ(store.get_target(url_key), nullptr);

    ddwaf_object_free(&root);
}

TEST(TestObjectStore, InsertAndGetObject)
{
    ddwaf::manifest_builder mb;
    auto query = mb.insert("query", {});
    auto query_key= mb.insert("query", {"key"});
    auto url = mb.insert("url", {});
    auto url_key = mb.insert("url", {"key"});
    auto manifest = mb.build_manifest();

    object_store store(manifest);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", ddwaf_object_string(&tmp, "hello"));

    store.insert(root);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(query_key));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.is_new_target(url_key));
    EXPECT_NE(store.get_target(query), nullptr);
    EXPECT_NE(store.get_target(query_key), nullptr);
    EXPECT_EQ(store.get_target(url), nullptr);
    EXPECT_EQ(store.get_target(url_key), nullptr);

    ddwaf_object_free(&root);
}

TEST(TestObjectStore, InsertMultipleUniqueObjects)
{
    ddwaf::manifest_builder mb;
    auto query = mb.insert("query", {});
    auto query_key= mb.insert("query", {"key"});
    auto url = mb.insert("url", {});
    auto url_key = mb.insert("url", {"key"});
    auto manifest = mb.build_manifest();

    object_store store(manifest);

    ddwaf_object first, second, third, tmp;
    ddwaf_object_map(&first);
    ddwaf_object_map_add(&first, "query", ddwaf_object_string(&tmp, "hello"));

    store.insert(first);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(query_key));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.is_new_target(url_key));
    EXPECT_NE(store.get_target(query), nullptr);
    EXPECT_NE(store.get_target(query_key), nullptr);
    EXPECT_EQ(store.get_target(url), nullptr);
    EXPECT_EQ(store.get_target(url_key), nullptr);

    ddwaf_object_map(&second);
    ddwaf_object_map_add(&second, "url", ddwaf_object_string(&tmp, "hello"));

    store.insert(second);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(query_key));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_TRUE(store.is_new_target(url_key));
    EXPECT_NE(store.get_target(query), nullptr);
    EXPECT_NE(store.get_target(query_key), nullptr);
    EXPECT_NE(store.get_target(url), nullptr);
    EXPECT_NE(store.get_target(url_key), nullptr);

    third = DDWAF_OBJECT_INVALID;
    store.insert(third);
    EXPECT_TRUE((bool)store);
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(query_key));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.is_new_target(url_key));
    EXPECT_NE(store.get_target(query), nullptr);
    EXPECT_NE(store.get_target(query_key), nullptr);
    EXPECT_NE(store.get_target(url), nullptr);
    EXPECT_NE(store.get_target(url_key), nullptr);

    ddwaf_object_free(&first);
    ddwaf_object_free(&second);
}

TEST(TestObjectStore, InsertMultipleOverlappingObjects)
{
    ddwaf::manifest_builder mb;
    auto query = mb.insert("query", {});
    auto query_key= mb.insert("query", {"key"});
    auto url = mb.insert("url", {});
    auto url_key = mb.insert("url", {"key"});
    auto manifest = mb.build_manifest();

    object_store store(manifest);

    ddwaf_object first, second, third, tmp;
    ddwaf_object_map(&first);
    ddwaf_object_map_add(&first, "query", ddwaf_object_string(&tmp, "hello"));
    store.insert(first);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(query_key));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.is_new_target(url_key));
    EXPECT_NE(store.get_target(query), nullptr);
    EXPECT_NE(store.get_target(query_key), nullptr);
    EXPECT_EQ(store.get_target(url), nullptr);
    EXPECT_EQ(store.get_target(url_key), nullptr);

    {
        const ddwaf_object *object = store.get_target(query);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        const ddwaf_object *object = store.get_target(query_key);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    // Reinsert query
    ddwaf_object_map(&second);
    ddwaf_object_map_add(&second, "url", ddwaf_object_string(&tmp, "hello"));
    ddwaf_object_map_add(&second, "query", ddwaf_object_string(&tmp, "bye"));
    store.insert(second);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(query_key));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_TRUE(store.is_new_target(url_key));

    {
        const ddwaf_object *object = store.get_target(url);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        const ddwaf_object *object = store.get_target(url_key);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        const ddwaf_object *object = store.get_target(query);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "bye");
    }

    {
        const ddwaf_object *object = store.get_target(query_key);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "bye");
    }

    // Reinsert url
    ddwaf_object_map(&third);
    ddwaf_object_map_add(&third, "url", ddwaf_object_string(&tmp, "bye"));
    store.insert(third);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(query_key));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_TRUE(store.is_new_target(url_key));
    EXPECT_NE(store.get_target(query), nullptr);
    EXPECT_NE(store.get_target(query_key), nullptr);

    {
        const ddwaf_object *object = store.get_target(url);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "bye");
    }

    {
        const ddwaf_object *object = store.get_target(url_key);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "bye");
    }

    ddwaf_object_free(&first);
    ddwaf_object_free(&second);
    ddwaf_object_free(&third);
}
