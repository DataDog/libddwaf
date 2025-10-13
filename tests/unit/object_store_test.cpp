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

    context_object_store store;
    store.insert(owned_object{});

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.get_target(query).first.has_value());
    EXPECT_FALSE(store.get_target(url).first.has_value());
}

TEST(TestObjectStore, InsertStringObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    context_object_store store;

    store.insert(owned_object::make_string("hello"));

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.get_target(query).first.has_value());
    EXPECT_FALSE(store.get_target(url).first.has_value());
}

TEST(TestObjectStore, InsertAndGetObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    auto root = owned_object::make_map();
    root.emplace("query", owned_object::make_string("hello"));

    context_object_store store;
    store.insert(std::move(root));

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).first.has_value());
    EXPECT_FALSE(store.get_target(url).first.has_value());
}

TEST(TestObjectStore, InsertAndGetSubcontextObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    context_object_store ctx_store;
    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};

        auto root = owned_object::make_map();
        root.emplace("query", owned_object::make_string("hello"));

        subcontext_object_store sctx_store{ctx_store};
        sctx_store.insert(std::move(root));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_TRUE(sctx_store.is_new_target(query));
        EXPECT_FALSE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).first.has_value());
        EXPECT_TRUE(sctx_store.get_target(query).second.is_subcontext());
        EXPECT_FALSE(sctx_store.get_target(url).first.has_value());
    }

    EXPECT_TRUE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_FALSE(ctx_store.get_target(query).first.has_value());
    EXPECT_FALSE(ctx_store.get_target(url).first.has_value());
}

TEST(TestObjectStore, InsertMultipleUniqueObjects)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    context_object_store ctx_store;

    {
        ctx_store.insert(object_builder::map({{"query", "hello"}}));

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_TRUE(ctx_store.has_new_targets());
        EXPECT_TRUE(ctx_store.is_new_target(query));
        EXPECT_FALSE(ctx_store.is_new_target(url));
        EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
        EXPECT_TRUE(ctx_store.get_target(query).second.is_context());
        EXPECT_FALSE(ctx_store.get_target(url).first.has_value());
    }

    {
        subcontext_object_store sctx_store{ctx_store};
        sctx_store.insert(object_builder::map({{"url", "hello"}}));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_TRUE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).first.has_value());
        EXPECT_TRUE(sctx_store.get_target(query).second.is_context());
        EXPECT_TRUE(sctx_store.get_target(url).first.has_value());
        EXPECT_TRUE(sctx_store.get_target(url).second.is_subcontext());
    }

    {
        ctx_store.insert(owned_object{});

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_TRUE(ctx_store.has_new_targets());
        EXPECT_TRUE(ctx_store.is_new_target(query));
        EXPECT_FALSE(ctx_store.is_new_target(url));
        EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
        EXPECT_TRUE(ctx_store.get_target(query).second.is_context());
        EXPECT_FALSE(ctx_store.get_target(url).first.has_value());
    }

    ctx_store.clear_last_batch();

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
    EXPECT_FALSE(ctx_store.get_target(url).first.has_value());
}

TEST(TestObjectStore, InsertMultipleUniqueObjectBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    context_object_store store;
    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

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
        defer cleanup{[&]() { store.clear_last_batch(); }};

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
        defer cleanup{[&]() { store.clear_last_batch(); }};

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

    context_object_store store;
    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

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
        EXPECT_TRUE(object.is_string());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

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
            EXPECT_TRUE(object.is_string());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            auto object = store.get_target(query).first;
            EXPECT_TRUE(object.has_value());
            EXPECT_TRUE(object.is_string());
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};
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
        EXPECT_TRUE(object.is_string());
        EXPECT_STRV(object.as<std::string_view>(), "bye");
    }
}

TEST(TestObjectStore, InsertSingleTargets)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    context_object_store ctx_store;

    ctx_store.insert(query, "query", owned_object::make_string("hello"));

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_TRUE(ctx_store.has_new_targets());
    EXPECT_TRUE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
    EXPECT_FALSE(ctx_store.get_target(url).first.has_value());

    {
        subcontext_object_store sctx_store{ctx_store};
        sctx_store.insert(url, "url", owned_object::make_string("hello"));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_TRUE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).first.has_value());
        EXPECT_TRUE(sctx_store.get_target(url).first.has_value());
    }

    ctx_store.clear_last_batch();

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
    EXPECT_FALSE(ctx_store.get_target(url).first.has_value());
}

TEST(TestObjectStore, InsertSingleTargetBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    context_object_store ctx_store;
    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};

        ctx_store.insert(query, "query", owned_object::make_string("hello"));

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_TRUE(ctx_store.has_new_targets());
        EXPECT_TRUE(ctx_store.is_new_target(query));
        EXPECT_FALSE(ctx_store.is_new_target(url));
        EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
        EXPECT_FALSE(ctx_store.get_target(url).first.has_value());
    }

    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};

        subcontext_object_store sctx_store{ctx_store};
        sctx_store.insert(url, "url", owned_object::make_string("hello"));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_FALSE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).first.has_value());
        EXPECT_TRUE(sctx_store.get_target(url).first.has_value());
    }

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
    EXPECT_FALSE(ctx_store.get_target(url).first.has_value());
}

TEST(TestObjectStore, DuplicatePersistentTarget)
{
    auto query = get_target_index("query");

    context_object_store store;
    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("hello")));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));

        auto [object, attr] = store.get_target(query);
        EXPECT_TRUE(attr.is_context());
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};

        EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("bye")));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_TRUE(store.get_target(query).first.has_value());

        auto [object, attr] = store.get_target(query);
        EXPECT_TRUE(attr.is_context());
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "bye");
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_TRUE(store.get_target(query).first.has_value());
}

TEST(TestObjectStore, DuplicateSubcontextTarget)
{
    auto query = get_target_index("query");

    subcontext_object_store store;

    {
        defer cleanup{[&]() { store.clear_last_batch(); }};
        {
            EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("hello")));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));

            auto [object, attr] = store.get_target(query);
            EXPECT_TRUE(attr.is_subcontext());
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            EXPECT_TRUE(store.insert(query, "query", owned_object::make_string("bye")));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));
            EXPECT_TRUE(store.get_target(query).first.has_value());

            auto [object, attr] = store.get_target(query);
            EXPECT_TRUE(attr.is_subcontext());
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_TRUE(store.get_target(query).first.has_value());
}

TEST(TestObjectStore, ReplaceSubcontextWithPersistent)
{
    auto query = get_target_index("query");

    context_object_store ctx_store;

    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};
        {
            subcontext_object_store sctx_store;
            EXPECT_TRUE(sctx_store.insert(query, "query", owned_object::make_string("hello")));

            EXPECT_FALSE(sctx_store.empty());
            EXPECT_TRUE(sctx_store.has_new_targets());
            EXPECT_TRUE(sctx_store.is_new_target(query));

            auto [object, attr] = sctx_store.get_target(query);
            EXPECT_TRUE(attr.is_subcontext());
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            EXPECT_TRUE(ctx_store.insert(query, "query", owned_object::make_string("bye")));

            EXPECT_FALSE(ctx_store.empty());
            EXPECT_TRUE(ctx_store.has_new_targets());
            EXPECT_TRUE(ctx_store.is_new_target(query));
            EXPECT_TRUE(ctx_store.get_target(query).first.has_value());

            auto [object, attr] = ctx_store.get_target(query);
            EXPECT_TRUE(attr.is_context());
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
}

TEST(TestObjectStore, ReplacePersistentWithSubcontextSameBatch)
{
    auto query = get_target_index("query");

    context_object_store ctx_store;

    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};
        {
            EXPECT_TRUE(ctx_store.insert(query, "query", owned_object::make_string("hello")));

            EXPECT_FALSE(ctx_store.empty());
            EXPECT_TRUE(ctx_store.has_new_targets());
            EXPECT_TRUE(ctx_store.is_new_target(query));

            auto [object, attr] = ctx_store.get_target(query);
            EXPECT_TRUE(attr.is_context());
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            subcontext_object_store sctx_store;
            EXPECT_TRUE(sctx_store.insert(query, "query", owned_object::make_string("bye")));

            EXPECT_FALSE(sctx_store.empty());
            EXPECT_TRUE(sctx_store.has_new_targets());
            EXPECT_TRUE(sctx_store.is_new_target(query));
            EXPECT_TRUE(sctx_store.get_target(query).first.has_value());

            auto [object, attr] = sctx_store.get_target(query);
            EXPECT_TRUE(attr.is_subcontext());
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
}

TEST(TestObjectStore, ReplacePersistentWithSubcontextDifferentBatch)
{
    auto query = get_target_index("query");

    context_object_store ctx_store;

    {
        defer cleanup{[&]() { ctx_store.clear_last_batch(); }};

        EXPECT_TRUE(ctx_store.insert(query, "query", owned_object::make_string("hello")));

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_TRUE(ctx_store.has_new_targets());
        EXPECT_TRUE(ctx_store.is_new_target(query));

        auto [object, attr] = ctx_store.get_target(query);
        EXPECT_TRUE(attr.is_context());
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        subcontext_object_store sctx_store{ctx_store};
        EXPECT_TRUE(sctx_store.insert(query, "query", owned_object::make_string("bye")));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_TRUE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.get_target(query).first.has_value());

        auto [object, attr] = sctx_store.get_target(query);
        EXPECT_TRUE(attr.is_subcontext());
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "bye");
    }

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_TRUE(ctx_store.get_target(query).first.has_value());
}

} // namespace
