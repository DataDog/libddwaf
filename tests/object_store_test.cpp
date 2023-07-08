// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestObjectStore, InsertInvalidObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;

    ddwaf_object root = DDWAF_OBJECT_INVALID;

    store.insert(root);

    EXPECT_FALSE((bool)store);
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_EQ(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);
}

TEST(TestObjectStore, InsertMalformedMap)
{

    object_store store;

    ddwaf_object root = DDWAF_OBJECT_MAP;
    root.nbEntries = 30;

    EXPECT_FALSE(store.insert(root));

    EXPECT_FALSE((bool)store);
}

TEST(TestObjectStore, InsertMalformedMapKey)
{
    get_target_index("key");

    object_store store;

    ddwaf_object tmp;
    ddwaf_object root = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&root, "key", ddwaf_object_string(&tmp, "value"));

    free((void *)root.array[0].parameterName);
    root.array[0].parameterName = nullptr;

    EXPECT_TRUE(store.insert(root));
    EXPECT_FALSE((bool)store);
}

TEST(TestObjectStore, InsertStringObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;

    ddwaf_object root;
    ddwaf_object_string(&root, "hello");

    store.insert(root);

    EXPECT_FALSE((bool)store);
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_EQ(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);
}

TEST(TestObjectStore, InsertAndGetObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "query", ddwaf_object_string(&tmp, "hello"));

    store.insert(root);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);
}

TEST(TestObjectStore, InsertMultipleUniqueObjects)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;

    ddwaf_object first;
    ddwaf_object second;
    ddwaf_object third;
    ddwaf_object tmp;
    ddwaf_object_map(&first);
    ddwaf_object_map_add(&first, "query", ddwaf_object_string(&tmp, "hello"));

    store.insert(first);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);

    ddwaf_object_map(&second);
    ddwaf_object_map_add(&second, "url", ddwaf_object_string(&tmp, "hello"));

    store.insert(second);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_NE(store.get_target(url).first, nullptr);

    third = DDWAF_OBJECT_INVALID;
    store.insert(third);
    EXPECT_TRUE((bool)store);
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_NE(store.get_target(url).first, nullptr);
}

TEST(TestObjectStore, InsertMultipleOverlappingObjects)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;

    ddwaf_object first;
    ddwaf_object second;
    ddwaf_object third;
    ddwaf_object tmp;
    ddwaf_object_map(&first);
    ddwaf_object_map_add(&first, "query", ddwaf_object_string(&tmp, "hello"));
    store.insert(first);

    EXPECT_TRUE((bool)store);
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);

    {
        auto [object, attr] = store.get_target(query);
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
    EXPECT_TRUE(store.is_new_target(url));

    {
        auto [object, attr] = store.get_target(url);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        auto [object, attr] = store.get_target(query);
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
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);

    {
        auto [object, attr] = store.get_target(url);
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "bye");
    }
}
