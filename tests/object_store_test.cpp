// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

ddwaf::manifest get_manifest()
{
    ddwaf::manifest manifest;
    manifest.insert("query", "query");
    manifest.insert("query++", "query");
    manifest.insert("url", "url");
    manifest.insert("url++", "url");
    return manifest;
}

TEST(TestObjectStore, InsertInvalidObject)
{
    auto manifest = get_manifest();

    object_store store(manifest);

    ddwaf_object root = DDWAF_OBJECT_INVALID;

    store.insert(root);

    EXPECT_FALSE((bool)store);
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target("query"));
    EXPECT_FALSE(store.is_new_target("query++"));
    EXPECT_FALSE(store.is_new_target("url"));
    EXPECT_FALSE(store.is_new_target("url++"));
    EXPECT_EQ(store.get_target("query"), nullptr);
    EXPECT_EQ(store.get_target("query++"), nullptr);
    EXPECT_EQ(store.get_target("url"), nullptr);
    EXPECT_EQ(store.get_target("url++"), nullptr);

    ddwaf_object_free(&root);
}

TEST(TestObjectStore, InsertStringObject)
{
    auto manifest = get_manifest();

    object_store store(manifest);

    ddwaf_object root;
    ddwaf_object_string(&root, "hello");

    store.insert(root);

    EXPECT_FALSE((bool)store);
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target("query"));
    EXPECT_FALSE(store.is_new_target("query++"));
    EXPECT_FALSE(store.is_new_target("url"));
    EXPECT_FALSE(store.is_new_target("url++"));
    EXPECT_EQ(store.get_target("query"), nullptr);
    EXPECT_EQ(store.get_target("query++"), nullptr);
    EXPECT_EQ(store.get_target("url"), nullptr);
    EXPECT_EQ(store.get_target("url++"), nullptr);

    ddwaf_object_free(&root);
}

TEST(TestObjectStore, InsertAndGetObject)
{
    auto manifest = get_manifest();

    object_store store(manifest);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", ddwaf_object_string(&tmp, "hello"));

    store.insert(root);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target("query"));
    EXPECT_TRUE(store.is_new_target("query++"));
    EXPECT_FALSE(store.is_new_target("url"));
    EXPECT_FALSE(store.is_new_target("url++"));
    EXPECT_NE(store.get_target("query"), nullptr);
    EXPECT_NE(store.get_target("query++"), nullptr);
    EXPECT_EQ(store.get_target("url"), nullptr);
    EXPECT_EQ(store.get_target("url++"), nullptr);

    ddwaf_object_free(&root);
}

TEST(TestObjectStore, InsertMultipleUniqueObjects)
{
    auto manifest = get_manifest();

    object_store store(manifest);

    ddwaf_object first, second, third, tmp;
    ddwaf_object_map(&first);
    ddwaf_object_map_add(&first, "query", ddwaf_object_string(&tmp, "hello"));

    store.insert(first);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target("query"));
    EXPECT_TRUE(store.is_new_target("query++"));
    EXPECT_FALSE(store.is_new_target("url"));
    EXPECT_FALSE(store.is_new_target("url++"));
    EXPECT_NE(store.get_target("query"), nullptr);
    EXPECT_NE(store.get_target("query++"), nullptr);
    EXPECT_EQ(store.get_target("url"), nullptr);
    EXPECT_EQ(store.get_target("url++"), nullptr);

    ddwaf_object_map(&second);
    ddwaf_object_map_add(&second, "url", ddwaf_object_string(&tmp, "hello"));

    store.insert(second);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target("query"));
    EXPECT_FALSE(store.is_new_target("query++"));
    EXPECT_TRUE(store.is_new_target("url"));
    EXPECT_TRUE(store.is_new_target("url++"));
    EXPECT_NE(store.get_target("query"), nullptr);
    EXPECT_NE(store.get_target("query++"), nullptr);
    EXPECT_NE(store.get_target("url"), nullptr);
    EXPECT_NE(store.get_target("url++"), nullptr);

    third = DDWAF_OBJECT_INVALID;
    store.insert(third);
    EXPECT_TRUE((bool)store);
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target("query"));
    EXPECT_FALSE(store.is_new_target("query++"));
    EXPECT_FALSE(store.is_new_target("url"));
    EXPECT_FALSE(store.is_new_target("url++"));
    EXPECT_NE(store.get_target("query"), nullptr);
    EXPECT_NE(store.get_target("query++"), nullptr);
    EXPECT_NE(store.get_target("url"), nullptr);
    EXPECT_NE(store.get_target("url++"), nullptr);

    ddwaf_object_free(&first);
    ddwaf_object_free(&second);
}

TEST(TestObjectStore, InsertMultipleOverlappingObjects)
{
    auto manifest = get_manifest();

    object_store store(manifest);

    ddwaf_object first, second, third, tmp;
    ddwaf_object_map(&first);
    ddwaf_object_map_add(&first, "query", ddwaf_object_string(&tmp, "hello"));
    store.insert(first);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target("query"));
    EXPECT_TRUE(store.is_new_target("query++"));
    EXPECT_FALSE(store.is_new_target("url"));
    EXPECT_FALSE(store.is_new_target("url++"));
    EXPECT_NE(store.get_target("query"), nullptr);
    EXPECT_NE(store.get_target("query++"), nullptr);
    EXPECT_EQ(store.get_target("url"), nullptr);
    EXPECT_EQ(store.get_target("url++"), nullptr);

    {
        const ddwaf_object *object = store.get_target("query");
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        const ddwaf_object *object = store.get_target("query++");
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
    EXPECT_TRUE(store.is_new_target("query"));
    EXPECT_TRUE(store.is_new_target("query++"));
    EXPECT_TRUE(store.is_new_target("url"));
    EXPECT_TRUE(store.is_new_target("url++"));

    {
        const ddwaf_object *object = store.get_target("url");
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        const ddwaf_object *object = store.get_target("url++");
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        const ddwaf_object *object = store.get_target("query");
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "bye");
    }

    {
        const ddwaf_object *object = store.get_target("query++");
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
    EXPECT_FALSE(store.is_new_target("query"));
    EXPECT_FALSE(store.is_new_target("query++"));
    EXPECT_TRUE(store.is_new_target("url"));
    EXPECT_TRUE(store.is_new_target("url++"));
    EXPECT_NE(store.get_target("query"), nullptr);
    EXPECT_NE(store.get_target("query++"), nullptr);

    {
        const ddwaf_object *object = store.get_target("url");
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "bye");
    }

    {
        const ddwaf_object *object = store.get_target("url++");
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "bye");
    }

    ddwaf_object_free(&first);
    ddwaf_object_free(&second);
    ddwaf_object_free(&third);
}
