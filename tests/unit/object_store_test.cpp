// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "object_store.hpp"

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestObjectStore, InsertInvalidObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    // An empty owned_object is not a map, so insert_batch returns false and
    // nothing is queued; no next_batch() call needed.
    store.insert_batch(owned_object{});

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.get_target(query).has_value());
    EXPECT_FALSE(store.get_target(url).has_value());
}

TEST(TestObjectStore, InsertStringObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;

    // A string is not a map, so insert_batch returns false and nothing is
    // queued; no next_batch() call needed.
    store.insert_batch(test::ddwaf_object_da::make_string("hello"));

    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_FALSE(store.get_target(query).has_value());
    EXPECT_FALSE(store.get_target(url).has_value());
}

TEST(TestObjectStore, InsertAndGetObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    auto root = test::ddwaf_object_da::make_map();
    root.emplace("query", test::ddwaf_object_da::make_string("hello"));

    object_store store;
    store.insert_and_apply(std::move(root));

    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).has_value());
    EXPECT_FALSE(store.get_target(url).has_value());
}

TEST(TestObjectStore, InsertAndApplyInvalidObject)
{
    object_store store;
    EXPECT_FALSE(store.insert_and_apply(owned_object{}));
    EXPECT_TRUE(store.empty());
    EXPECT_FALSE(store.next_batch());
}

TEST(TestObjectStore, InsertAndGetSubcontextObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store ctx_store;
    {
        defer cleanup{[&]() { ctx_store.flush_input_queue(); }};

        auto root = test::ddwaf_object_da::make_map();
        root.emplace("query", test::ddwaf_object_da::make_string("hello"));

        auto sctx_store = object_store::from_upstream_store(ctx_store);
        sctx_store.insert_and_apply(std::move(root));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_TRUE(sctx_store.is_new_target(query));
        EXPECT_FALSE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).has_value());
        EXPECT_FALSE(sctx_store.get_target(url).has_value());
    }

    EXPECT_TRUE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_FALSE(ctx_store.get_target(query).has_value());
    EXPECT_FALSE(ctx_store.get_target(url).has_value());
}

TEST(TestObjectStore, InsertMultipleUniqueObjects)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store ctx_store;

    {
        ctx_store.insert_and_apply(object_builder_da::map({{"query", "hello"}}));

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_TRUE(ctx_store.has_new_targets());
        EXPECT_TRUE(ctx_store.is_new_target(query));
        EXPECT_FALSE(ctx_store.is_new_target(url));
        EXPECT_TRUE(ctx_store.get_target(query).has_value());
        EXPECT_FALSE(ctx_store.get_target(url).has_value());
    }

    {
        auto sctx_store = object_store::from_upstream_store(ctx_store);
        sctx_store.insert_and_apply(object_builder_da::map({{"url", "hello"}}));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_TRUE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).has_value());
        EXPECT_TRUE(sctx_store.get_target(url).has_value());
    }

    {
        // An empty owned_object is not a map, so nothing is queued; latest_batch_
        // still contains query from the first insert above.
        ctx_store.insert_batch(owned_object{});

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_TRUE(ctx_store.has_new_targets());
        EXPECT_TRUE(ctx_store.is_new_target(query));
        EXPECT_FALSE(ctx_store.is_new_target(url));
        EXPECT_TRUE(ctx_store.get_target(query).has_value());
        EXPECT_FALSE(ctx_store.get_target(url).has_value());
    }

    ctx_store.flush_input_queue();

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).has_value());
    EXPECT_FALSE(ctx_store.get_target(url).has_value());
}

TEST(TestObjectStore, InsertBatchesWithInvalidElement)
{
    object_store store;

    auto batches =
        object_builder_da::array({object_builder_da::map({{"query", "hello"}}), "invalid"});
    EXPECT_FALSE(store.insert_batches(object_view{batches}.as<array_view>()));
    EXPECT_FALSE(store.next_batch());
    EXPECT_TRUE(store.empty());
}

TEST(TestObjectStore, FlushAppliesQueuedBatchesWithoutMarkingNewTargets)
{
    object_store store;

    auto batches = object_builder_da::array(
        {object_builder_da::map({{"query", "hello"}}), object_builder_da::map({{"url", "world"}})});
    ASSERT_TRUE(store.insert_batches(std::move(batches)));

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.get_target("query").has_value());
    EXPECT_FALSE(store.get_target("url").has_value());

    store.flush_input_queue();

    EXPECT_TRUE(store.get_target("query").has_value());
    EXPECT_TRUE(store.get_target("url").has_value());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.next_batch());
}

TEST(TestObjectStore, InsertMultipleUniqueObjectBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        defer cleanup{[&]() { store.flush_input_queue(); }};

        auto first = test::ddwaf_object_da::make_map();
        first.emplace("query", test::ddwaf_object_da::make_string("hello"));

        store.insert_and_apply(std::move(first));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).has_value());
        EXPECT_FALSE(store.get_target(url).has_value());
    }

    {
        defer cleanup{[&]() { store.flush_input_queue(); }};

        auto second = test::ddwaf_object_da::make_map();
        second.emplace("url", test::ddwaf_object_da::make_string("hello"));

        store.insert_and_apply(std::move(second));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).has_value());
        EXPECT_TRUE(store.get_target(url).has_value());
    }

    {
        defer cleanup{[&]() { store.flush_input_queue(); }};

        // An empty owned_object is not a map, so nothing is queued; latest_batch_
        // was already cleared by the previous flush_input_queue().
        owned_object third = owned_object{};
        store.insert_batch(std::move(third));
        EXPECT_FALSE(store.empty());
        EXPECT_FALSE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).has_value());
        EXPECT_TRUE(store.get_target(url).has_value());
    }
}

TEST(TestObjectStore, InsertMultipleOverlappingObjects)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        defer cleanup{[&]() { store.flush_input_queue(); }};

        auto first = test::ddwaf_object_da::make_map();
        first.emplace("query", test::ddwaf_object_da::make_string("hello"));
        store.insert_and_apply(std::move(first));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_FALSE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).has_value());
        EXPECT_FALSE(store.get_target(url).has_value());

        auto object = store.get_target(query);
        EXPECT_TRUE(object.has_value());
        EXPECT_TRUE(object.is_string());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        defer cleanup{[&]() { store.flush_input_queue(); }};

        // Reinsert query
        auto second = test::ddwaf_object_da::make_map();
        second.emplace("url", test::ddwaf_object_da::make_string("hello"));
        second.emplace("query", test::ddwaf_object_da::make_string("bye"));
        store.insert_and_apply(std::move(second));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));

        {
            auto object = store.get_target(url);
            EXPECT_TRUE(object.has_value());
            EXPECT_TRUE(object.is_string());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            auto object = store.get_target(query);
            EXPECT_TRUE(object.has_value());
            EXPECT_TRUE(object.is_string());
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    {
        defer cleanup{[&]() { store.flush_input_queue(); }};
        // Reinsert url
        auto third = test::ddwaf_object_da::make_map();
        third.emplace("url", test::ddwaf_object_da::make_string("bye"));
        store.insert_and_apply(std::move(third));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_FALSE(store.is_new_target(query));
        EXPECT_TRUE(store.is_new_target(url));
        EXPECT_TRUE(store.get_target(query).has_value());

        auto object = store.get_target(url);
        EXPECT_TRUE(object.has_value());
        EXPECT_TRUE(object.is_string());
        EXPECT_STRV(object.as<std::string_view>(), "bye");
    }
}

TEST(TestObjectStore, InsertSingleTargets)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store ctx_store;

    ctx_store.insert_target(query, "query", test::ddwaf_object_da::make_string("hello"));

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_TRUE(ctx_store.has_new_targets());
    EXPECT_TRUE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).has_value());
    EXPECT_FALSE(ctx_store.get_target(url).has_value());

    {
        auto sctx_store = object_store::from_upstream_store(ctx_store);
        sctx_store.insert_target(url, "url", test::ddwaf_object_da::make_string("hello"));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_TRUE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).has_value());
        EXPECT_TRUE(sctx_store.get_target(url).has_value());
    }

    ctx_store.flush_input_queue();

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).has_value());
    EXPECT_FALSE(ctx_store.get_target(url).has_value());
}

TEST(TestObjectStore, InsertSingleTargetBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store ctx_store;
    {
        defer cleanup{[&]() { ctx_store.flush_input_queue(); }};

        ctx_store.insert_target(query, "query", test::ddwaf_object_da::make_string("hello"));

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_TRUE(ctx_store.has_new_targets());
        EXPECT_TRUE(ctx_store.is_new_target(query));
        EXPECT_FALSE(ctx_store.is_new_target(url));
        EXPECT_TRUE(ctx_store.get_target(query).has_value());
        EXPECT_FALSE(ctx_store.get_target(url).has_value());
    }

    {
        defer cleanup{[&]() { ctx_store.flush_input_queue(); }};

        auto sctx_store = object_store::from_upstream_store(ctx_store);
        sctx_store.insert_target(url, "url", test::ddwaf_object_da::make_string("hello"));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_FALSE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).has_value());
        EXPECT_TRUE(sctx_store.get_target(url).has_value());
    }

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).has_value());
    EXPECT_FALSE(ctx_store.get_target(url).has_value());
}

TEST(TestObjectStore, DuplicatePersistentTarget)
{
    auto query = get_target_index("query");

    object_store store;
    {
        defer cleanup{[&]() { store.flush_input_queue(); }};

        EXPECT_TRUE(
            store.insert_target(query, "query", test::ddwaf_object_da::make_string("hello")));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));

        auto object = store.get_target(query);
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        defer cleanup{[&]() { store.flush_input_queue(); }};

        EXPECT_TRUE(store.insert_target(query, "query", test::ddwaf_object_da::make_string("bye")));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));
        EXPECT_TRUE(store.get_target(query).has_value());

        auto object = store.get_target(query);
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "bye");
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_TRUE(store.get_target(query).has_value());
}

TEST(TestObjectStore, DuplicateSubcontextTarget)
{
    auto query = get_target_index("query");

    object_store store;

    {
        defer cleanup{[&]() { store.flush_input_queue(); }};
        {
            EXPECT_TRUE(
                store.insert_target(query, "query", test::ddwaf_object_da::make_string("hello")));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));

            auto object = store.get_target(query);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            EXPECT_TRUE(
                store.insert_target(query, "query", test::ddwaf_object_da::make_string("bye")));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));
            EXPECT_TRUE(store.get_target(query).has_value());

            auto object = store.get_target(query);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    EXPECT_FALSE(store.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_TRUE(store.get_target(query).has_value());
}

TEST(TestObjectStore, ReplaceSubcontextWithPersistent)
{
    auto query = get_target_index("query");

    object_store ctx_store;

    {
        defer cleanup{[&]() { ctx_store.flush_input_queue(); }};
        {
            object_store sctx_store;
            EXPECT_TRUE(sctx_store.insert_target(
                query, "query", test::ddwaf_object_da::make_string("hello")));

            EXPECT_FALSE(sctx_store.empty());
            EXPECT_TRUE(sctx_store.has_new_targets());
            EXPECT_TRUE(sctx_store.is_new_target(query));

            auto object = sctx_store.get_target(query);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            EXPECT_TRUE(
                ctx_store.insert_target(query, "query", test::ddwaf_object_da::make_string("bye")));

            EXPECT_FALSE(ctx_store.empty());
            EXPECT_TRUE(ctx_store.has_new_targets());
            EXPECT_TRUE(ctx_store.is_new_target(query));
            EXPECT_TRUE(ctx_store.get_target(query).has_value());

            auto object = ctx_store.get_target(query);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_TRUE(ctx_store.get_target(query).has_value());
}

TEST(TestObjectStore, ReplacePersistentWithSubcontextSameBatch)
{
    auto query = get_target_index("query");

    object_store ctx_store;

    {
        defer cleanup{[&]() { ctx_store.flush_input_queue(); }};
        {
            EXPECT_TRUE(ctx_store.insert_target(
                query, "query", test::ddwaf_object_da::make_string("hello")));

            EXPECT_FALSE(ctx_store.empty());
            EXPECT_TRUE(ctx_store.has_new_targets());
            EXPECT_TRUE(ctx_store.is_new_target(query));

            auto object = ctx_store.get_target(query);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            object_store sctx_store;
            EXPECT_TRUE(sctx_store.insert_target(
                query, "query", test::ddwaf_object_da::make_string("bye")));

            EXPECT_FALSE(sctx_store.empty());
            EXPECT_TRUE(sctx_store.has_new_targets());
            EXPECT_TRUE(sctx_store.is_new_target(query));
            EXPECT_TRUE(sctx_store.get_target(query).has_value());

            auto object = sctx_store.get_target(query);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "bye");
        }
    }

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_TRUE(ctx_store.get_target(query).has_value());
}

TEST(TestObjectStore, ReplacePersistentWithSubcontextDifferentBatch)
{
    auto query = get_target_index("query");

    object_store ctx_store;

    {
        defer cleanup{[&]() { ctx_store.flush_input_queue(); }};

        EXPECT_TRUE(
            ctx_store.insert_target(query, "query", test::ddwaf_object_da::make_string("hello")));

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_TRUE(ctx_store.has_new_targets());
        EXPECT_TRUE(ctx_store.is_new_target(query));

        auto object = ctx_store.get_target(query);
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        auto sctx_store = object_store::from_upstream_store(ctx_store);
        EXPECT_TRUE(
            sctx_store.insert_target(query, "query", test::ddwaf_object_da::make_string("bye")));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_TRUE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.get_target(query).has_value());

        auto object = sctx_store.get_target(query);
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "bye");
    }

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_TRUE(ctx_store.get_target(query).has_value());
}

} // namespace
