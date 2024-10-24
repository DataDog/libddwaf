// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "object_store.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestObjectStore, InsertInvalidObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();
        ddwaf_object root = DDWAF_OBJECT_INVALID;

        store.insert(root);

        EXPECT_TRUE(store.empty());
        EXPECT_FALSE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_EQ(store.get_target(query).first, nullptr);
        EXPECT_EQ(store.get_target(url).first, nullptr);
    }
}

TEST(TestObjectStore, InsertMalformedMap)
{
    object_store store;
    {
        auto scope = store.get_eval_scope();
        ddwaf_object root = DDWAF_OBJECT_MAP;
        root.nbEntries = 30;

        EXPECT_FALSE(store.insert(root));

        EXPECT_TRUE(store.empty());
    }
}

TEST(TestObjectStore, InsertMalformedMapKey)
{
    get_target_index("key");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        ddwaf_object tmp;
        ddwaf_object root = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&root, "key", ddwaf_object_string(&tmp, "value"));

        // NOLINTNEXTLINE
        free((void *)root.array[0].parameterName);
        root.array[0].parameterName = nullptr;

        EXPECT_TRUE(store.insert(root));
        EXPECT_TRUE(store.empty());
    }
}

TEST(TestObjectStore, InsertStringObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object_string(&root, "hello");

        store.insert(root);

        EXPECT_TRUE(store.empty());
        EXPECT_FALSE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_EQ(store.get_target(query).first, nullptr);
        EXPECT_EQ(store.get_target(url).first, nullptr);
    }
}

TEST(TestObjectStore, InsertAndGetObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", ddwaf_object_string(&tmp, "hello"));

        store.insert(root);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_NE(store.get_target(query).first, nullptr);
        EXPECT_EQ(store.get_target(url).first, nullptr);
    }
}

TEST(TestObjectStore, InsertAndGetEphemeralObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "query", ddwaf_object_string(&tmp, "hello"));

        store.insert(root, object_store::attribute::ephemeral);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_NE(store.get_target(query).first, nullptr);
        EXPECT_EQ(store.get_target(query).second, object_store::attribute::ephemeral);
        EXPECT_EQ(store.get_target(url).first, nullptr);
    }

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_EQ(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);
}

TEST(TestObjectStore, InsertMultipleUniqueObjects)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    ddwaf_object tmp;

    object_store store;
    {
        ddwaf_object first;
        ddwaf_object_map(&first);
        ddwaf_object_map_add(&first, "query", ddwaf_object_string(&tmp, "hello"));

        store.insert(first);
    }

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);

    {
        ddwaf_object second;
        ddwaf_object_map(&second);
        ddwaf_object_map_add(&second, "url", ddwaf_object_string(&tmp, "hello"));
        store.insert(second, object_store::attribute::ephemeral);
    }

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_NE(store.get_target(url).first, nullptr);

    {
        ddwaf_object third = DDWAF_OBJECT_INVALID;
        store.insert(third);
    }

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_NE(store.get_target(url).first, nullptr);

    store.clear_last_batch();

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);
}

TEST(TestObjectStore, InsertMultipleUniqueObjectBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    ddwaf_object tmp;

    object_store store;
    {
        auto scope = store.get_eval_scope();

        ddwaf_object first;
        ddwaf_object_map(&first);
        ddwaf_object_map_add(&first, "query", ddwaf_object_string(&tmp, "hello"));

        store.insert(first);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_NE(store.get_target(query).first, nullptr);
        EXPECT_EQ(store.get_target(url).first, nullptr);
    }

    {
        auto scope = store.get_eval_scope();

        ddwaf_object second;
        ddwaf_object_map(&second);
        ddwaf_object_map_add(&second, "url", ddwaf_object_string(&tmp, "hello"));

        store.insert(second);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));
        EXPECT_NE(store.get_target(query).first, nullptr);
        EXPECT_NE(store.get_target(url).first, nullptr);
    }

    {
        auto scope = store.get_eval_scope();

        ddwaf_object third = DDWAF_OBJECT_INVALID;
        store.insert(third);
        EXPECT_FALSE(store.empty());
        EXPECT_FALSE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_NE(store.get_target(query).first, nullptr);
        EXPECT_NE(store.get_target(url).first, nullptr);
    }
}

TEST(TestObjectStore, InsertMultipleOverlappingObjects)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    ddwaf_object tmp;

    object_store store;
    {
        auto scope = store.get_eval_scope();

        ddwaf_object first;
        ddwaf_object_map(&first);
        ddwaf_object_map_add(&first, "query", ddwaf_object_string(&tmp, "hello"));
        store.insert(first);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_NE(store.get_target(query).first, nullptr);
        EXPECT_EQ(store.get_target(url).first, nullptr);

        auto *object = store.get_target(query).first;
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        auto scope = store.get_eval_scope();

        // Reinsert query
        ddwaf_object second;
        ddwaf_object_map(&second);
        ddwaf_object_map_add(&second, "url", ddwaf_object_string(&tmp, "hello"));
        ddwaf_object_map_add(&second, "query", ddwaf_object_string(&tmp, "bye"));
        store.insert(second);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));

        {
            auto *object = store.get_target(url).first;
            EXPECT_NE(object, nullptr);
            EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
            EXPECT_STREQ(object->stringValue, "hello");
        }

        {
            auto *object = store.get_target(query).first;
            EXPECT_NE(object, nullptr);
            EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
            EXPECT_STREQ(object->stringValue, "bye");
        }
    }

    {
        auto scope = store.get_eval_scope();
        // Reinsert url
        ddwaf_object third;
        ddwaf_object_map(&third);
        ddwaf_object_map_add(&third, "url", ddwaf_object_string(&tmp, "bye"));
        store.insert(third);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));
        EXPECT_NE(store.get_target(query).first, nullptr);

        auto *object = store.get_target(url).first;
        EXPECT_NE(object, nullptr);
        EXPECT_EQ(object->type, DDWAF_OBJ_STRING);
        EXPECT_STREQ(object->stringValue, "bye");
    }
}

TEST(TestObjectStore, InsertSingleTargets)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;

    ddwaf_object first;
    ddwaf_object_string(&first, "hello");

    store.insert(query, "query", first);

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);

    ddwaf_object second;
    ddwaf_object_string(&second, "hello");

    store.insert(url, "url", second, object_store::attribute::ephemeral);

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_NE(store.get_target(url).first, nullptr);

    store.clear_last_batch();

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);
}

TEST(TestObjectStore, InsertSingleTargetBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        ddwaf_object first;
        ddwaf_object_string(&first, "hello");

        store.insert(query, "query", first);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_NE(store.get_target(query).first, nullptr);
        EXPECT_EQ(store.get_target(url).first, nullptr);
    }

    {
        auto scope = store.get_eval_scope();

        ddwaf_object second;
        ddwaf_object_string(&second, "hello");

        store.insert(url, "url", second, object_store::attribute::ephemeral);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));
        EXPECT_NE(store.get_target(query).first, nullptr);
        EXPECT_NE(store.get_target(url).first, nullptr);
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_NE(store.get_target(query).first, nullptr);
    EXPECT_EQ(store.get_target(url).first, nullptr);
}

TEST(TestObjectStore, DuplicatePersistentTarget)
{
    auto query = get_target_index("query");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object_string(&root, "hello");

        EXPECT_TRUE(store.insert(query, "query", root));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));

        auto [object, attr] = store.get_target(query);
        EXPECT_EQ(attr, object_store::attribute::none);
        EXPECT_NE(object, nullptr);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object_string(&root, "bye");

        EXPECT_TRUE(store.insert(query, "query", root));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_NE(store.get_target(query).first, nullptr);

        auto [object, attr] = store.get_target(query);
        EXPECT_EQ(attr, object_store::attribute::none);
        EXPECT_NE(object, nullptr);
        EXPECT_STREQ(object->stringValue, "bye");
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_NE(store.get_target(query).first, nullptr);
}

TEST(TestObjectStore, DuplicateEphemeralTarget)
{
    auto query = get_target_index("query");

    object_store store;

    {
        auto scope = store.get_eval_scope();
        {

            ddwaf_object root;
            ddwaf_object_string(&root, "hello");

            EXPECT_TRUE(store.insert(query, "query", root, object_store::attribute::ephemeral));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::ephemeral);
            EXPECT_NE(object, nullptr);
            EXPECT_STREQ(object->stringValue, "hello");
        }

        {
            ddwaf_object root;
            ddwaf_object_string(&root, "bye");

            EXPECT_TRUE(store.insert(query, "query", root, object_store::attribute::ephemeral));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));
            EXPECT_NE(store.get_target(query).first, nullptr);

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::ephemeral);
            EXPECT_NE(object, nullptr);
            EXPECT_STREQ(object->stringValue, "bye");
        }
    }

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_EQ(store.get_target(query).first, nullptr);
}

TEST(TestObjectStore, FailtoReplaceEphemeralWithPersistent)
{
    auto query = get_target_index("query");

    object_store store;

    {
        auto scope = store.get_eval_scope();
        {

            ddwaf_object root;
            ddwaf_object_string(&root, "hello");

            EXPECT_TRUE(store.insert(query, "query", root, object_store::attribute::ephemeral));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::ephemeral);
            EXPECT_NE(object, nullptr);
            EXPECT_STREQ(object->stringValue, "hello");
        }

        {
            ddwaf_object root;
            ddwaf_object_string(&root, "bye");

            EXPECT_FALSE(store.insert(query, "query", root));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));
            EXPECT_NE(store.get_target(query).first, nullptr);

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::ephemeral);
            EXPECT_NE(object, nullptr);
            EXPECT_STREQ(object->stringValue, "hello");
        }
    }

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_EQ(store.get_target(query).first, nullptr);
}

TEST(TestObjectStore, FailToReplacePersistentWithEphemeralSameBatch)
{
    auto query = get_target_index("query");

    object_store store;

    {
        auto scope = store.get_eval_scope();
        {

            ddwaf_object root;
            ddwaf_object_string(&root, "hello");

            EXPECT_TRUE(store.insert(query, "query", root));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::none);
            EXPECT_NE(object, nullptr);
            EXPECT_STREQ(object->stringValue, "hello");
        }

        {
            ddwaf_object root;
            ddwaf_object_string(&root, "bye");

            EXPECT_FALSE(store.insert(query, "query", root, object_store::attribute::ephemeral));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));
            EXPECT_NE(store.get_target(query).first, nullptr);

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::none);
            EXPECT_NE(object, nullptr);
            EXPECT_STREQ(object->stringValue, "hello");
        }
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_NE(store.get_target(query).first, nullptr);
}

TEST(TestObjectStore, FailToReplacePersistentWithEphemeralDifferentBatch)
{
    auto query = get_target_index("query");

    object_store store;

    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object_string(&root, "hello");

        EXPECT_TRUE(store.insert(query, "query", root));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));

        auto [object, attr] = store.get_target(query);
        EXPECT_EQ(attr, object_store::attribute::none);
        EXPECT_NE(object, nullptr);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    {
        auto scope = store.get_eval_scope();

        ddwaf_object root;
        ddwaf_object_string(&root, "bye");

        EXPECT_FALSE(store.insert(query, "query", root, object_store::attribute::ephemeral));

        EXPECT_FALSE(store.empty());
        EXPECT_FALSE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_NE(store.get_target(query).first, nullptr);

        auto [object, attr] = store.get_target(query);
        EXPECT_EQ(attr, object_store::attribute::none);
        EXPECT_NE(object, nullptr);
        EXPECT_STREQ(object->stringValue, "hello");
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_NE(store.get_target(query).first, nullptr);
}

} // namespace
