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
        owned_object root;

        store.insert(std::move(root));

        EXPECT_TRUE(store.empty());
        EXPECT_FALSE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_FALSE(store.get_target(query).first.has_value());
        EXPECT_FALSE(store.get_target(url).first.has_value());
    }
}

TEST(TestObjectStore, InsertStringObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        store.insert(owned_object::make_string("hello"));

        EXPECT_TRUE(store.empty());
        EXPECT_FALSE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_FALSE(store.get_target(query).first.has_value());
        EXPECT_FALSE(store.get_target(url).first.has_value());
    }
}

TEST(TestObjectStore, InsertAndGetObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map();
        root.emplace("query", owned_object::make_string("hello"));

        store.insert(std::move(root));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).first.has_value());
        EXPECT_FALSE(store.get_target(url).first.has_value());
    }
}

TEST(TestObjectStore, InsertAndGetEphemeralObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        auto root = owned_object::make_map();
        root.emplace("query", owned_object::make_string("hello"));

        store.insert(std::move(root), object_store::attribute::ephemeral);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).first.has_value());
        EXPECT_EQ(store.get_target(query).second, object_store::attribute::ephemeral);
        EXPECT_FALSE(store.get_target(url).first.has_value());
    }

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.get_target(query).first.has_value());
    EXPECT_FALSE(store.get_target(url).first.has_value());
}

TEST(TestObjectStore, InsertMultipleUniqueObjects)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto first = owned_object::make_map();
        first.emplace("query", owned_object::make_string("hello"));

        store.insert(std::move(first));
    }

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).first.has_value());
    EXPECT_FALSE(store.get_target(url).first.has_value());

    {
        auto second = owned_object::make_map();
        second.emplace("url", owned_object::make_string("hello"));
        store.insert(std::move(second), object_store::attribute::ephemeral);
    }

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).first.has_value());
    EXPECT_TRUE(store.get_target(url).first.has_value());

    {
        owned_object third;
        store.insert(std::move(third));
    }

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).first.has_value());
    EXPECT_TRUE(store.get_target(url).first.has_value());

    store.clear_last_batch();

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).first.has_value());
    EXPECT_FALSE(store.get_target(url).first.has_value());
}

TEST(TestObjectStore, InsertMultipleUniqueObjectBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        auto first = owned_object::make_map();
        first.emplace("query", owned_object::make_string("hello"));

        store.insert(std::move(first));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).first.has_value());
        EXPECT_FALSE(store.get_target(url).first.has_value());
    }

    {
        auto scope = store.get_eval_scope();

        auto second = owned_object::make_map();
        second.emplace("url", owned_object::make_string("hello"));

        store.insert(std::move(second));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).first.has_value());
        EXPECT_TRUE(store.get_target(url).first.has_value());
    }

    {
        auto scope = store.get_eval_scope();

        owned_object third;
        store.insert(std::move(third));
        EXPECT_FALSE(store.empty());
        EXPECT_FALSE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).first.has_value());
        EXPECT_TRUE(store.get_target(url).first.has_value());
    }
}

TEST(TestObjectStore, InsertMultipleOverlappingObjects)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        auto first = owned_object::make_map();
        first.emplace("query", owned_object::make_string("hello"));
        store.insert(std::move(first));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).first.has_value());
        EXPECT_FALSE(store.get_target(url).first.has_value());

        auto object = store.get_target(query).first;
        EXPECT_TRUE(object.has_value());
        EXPECT_EQ(object.type(), object_type::string);
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        auto scope = store.get_eval_scope();

        // Reinsert query
        auto second = owned_object::make_map();
        second.emplace("url", owned_object::make_string("hello"));
        second.emplace("query", owned_object::make_string("bye"));
        store.insert(std::move(second));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));

        {
            auto object = store.get_target(url).first;
            EXPECT_TRUE(object.has_value());
            EXPECT_EQ(object.type(), object_type::string);
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            auto object = store.get_target(query).first;
            EXPECT_TRUE(object.has_value());
            EXPECT_EQ(object.type(), object_type::string);
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    {
        auto scope = store.get_eval_scope();
        // Reinsert url
        auto third = owned_object::make_map();
        third.emplace("url", owned_object::make_string("bye"));
        store.insert(std::move(third));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).first.has_value());

        auto object = store.get_target(url).first;
        EXPECT_TRUE(object.has_value());
        EXPECT_EQ(object.type(), object_type::string);
        EXPECT_STRV(object.as<std::string_view>(), "bye");
    }
}

TEST(TestObjectStore, InsertSingleTargets)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;

    store.insert(query, "query", owned_object::make_string("hello"));

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).first.has_value());
    EXPECT_FALSE(store.get_target(url).first.has_value());

    store.insert(
        url, "url", owned_object::make_string("hello"), object_store::attribute::ephemeral);

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).first.has_value());
    EXPECT_TRUE(store.get_target(url).first.has_value());

    store.clear_last_batch();

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).first.has_value());
    EXPECT_FALSE(store.get_target(url).first.has_value());
}

TEST(TestObjectStore, InsertSingleTargetBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        store.insert(query, "query", owned_object::make_string("hello"));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).first.has_value());
        EXPECT_FALSE(store.get_target(url).first.has_value());
    }

    {
        auto scope = store.get_eval_scope();

        store.insert(
            url, "url", owned_object::make_string("hello"), object_store::attribute::ephemeral);

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).first.has_value());
        EXPECT_TRUE(store.get_target(url).first.has_value());
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).first.has_value());
    EXPECT_FALSE(store.get_target(url).first.has_value());
}

TEST(TestObjectStore, DuplicatePersistentTarget)
{
    auto query = get_target_index("query");

    object_store store;
    {
        auto scope = store.get_eval_scope();

        EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("hello")));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));

        auto [object, attr] = store.get_target(query);
        EXPECT_EQ(attr, object_store::attribute::none);
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        auto scope = store.get_eval_scope();

        EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("bye")));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_TRUE(store.get_target(query).first.has_value());

        auto [object, attr] = store.get_target(query);
        EXPECT_EQ(attr, object_store::attribute::none);
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "bye");
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_TRUE(store.get_target(query).first.has_value());
}

TEST(TestObjectStore, DuplicateEphemeralTarget)
{
    auto query = get_target_index("query");

    object_store store;

    {
        auto scope = store.get_eval_scope();
        {
            EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("hello"),
                object_store::attribute::ephemeral));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::ephemeral);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("bye"),
                object_store::attribute::ephemeral));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));
            EXPECT_TRUE(store.get_target(query).first.has_value());

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::ephemeral);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.get_target(query).first.has_value());
}

TEST(TestObjectStore, FailtoReplaceEphemeralWithPersistent)
{
    auto query = get_target_index("query");

    object_store store;

    {
        auto scope = store.get_eval_scope();
        {
            EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("hello"),
                object_store::attribute::ephemeral));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::ephemeral);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            EXPECT_FALSE(store.insert(query, "query", owned_object::make_string("bye")));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));
            EXPECT_TRUE(store.get_target(query).first.has_value());

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::ephemeral);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }
    }

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.get_target(query).first.has_value());
}

TEST(TestObjectStore, FailToReplacePersistentWithEphemeralSameBatch)
{
    auto query = get_target_index("query");

    object_store store;

    {
        auto scope = store.get_eval_scope();
        {
            EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("hello")));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::none);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            EXPECT_FALSE(store.insert(query, "query", owned_object::make_string("bye"),
                object_store::attribute::ephemeral));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));
            EXPECT_TRUE(store.get_target(query).first.has_value());

            auto [object, attr] = store.get_target(query);
            EXPECT_EQ(attr, object_store::attribute::none);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_TRUE(store.get_target(query).first.has_value());
}

TEST(TestObjectStore, FailToReplacePersistentWithEphemeralDifferentBatch)
{
    auto query = get_target_index("query");

    object_store store;

    {
        auto scope = store.get_eval_scope();

        EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("hello")));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));

        auto [object, attr] = store.get_target(query);
        EXPECT_EQ(attr, object_store::attribute::none);
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        auto scope = store.get_eval_scope();

        EXPECT_FALSE(store.insert(
            query, "query", owned_object::make_string("bye"), object_store::attribute::ephemeral));

        EXPECT_FALSE(store.empty());
        EXPECT_FALSE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_TRUE(store.get_target(query).first.has_value());

        auto [object, attr] = store.get_target(query);
        EXPECT_EQ(attr, object_store::attribute::none);
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_TRUE(store.get_target(query).first.has_value());
}

} // namespace
