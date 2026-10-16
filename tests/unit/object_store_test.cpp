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
    // An empty owned_object is not a map, so insert returns false and
    // the store is left untouched.
    store.insert_and_apply(owned_object{});

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

    // A string is not a map, so insert returns false and the store is
    // left untouched.
    store.insert_and_apply(test::ddwaf_object_da::make_string("hello"));

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

TEST(TestObjectStore, InsertAndGetSubcontextObject)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store ctx_store;
    {
        defer cleanup{[&]() { ctx_store.clear_latest_batch(); }};

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
        EXPECT_FALSE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).has_value());
        EXPECT_TRUE(sctx_store.get_target(url).has_value());
    }

    {
        // An empty map resets the new-target set (clearing query from the first
        // insert above) and is otherwise a no-op.
        ctx_store.insert_and_apply(object_builder_da::map({}));

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_FALSE(ctx_store.has_new_targets());
        EXPECT_FALSE(ctx_store.is_new_target(query));
        EXPECT_FALSE(ctx_store.is_new_target(url));
        EXPECT_TRUE(ctx_store.get_target(query).has_value());
        EXPECT_FALSE(ctx_store.get_target(url).has_value());
    }

    ctx_store.clear_latest_batch();

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_FALSE(ctx_store.has_new_targets());
    EXPECT_FALSE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).has_value());
    EXPECT_FALSE(ctx_store.get_target(url).has_value());
}

TEST(TestObjectStore, InsertMultipleUniqueObjectBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    {
        defer cleanup{[&]() { store.clear_latest_batch(); }};

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
        defer cleanup{[&]() { store.clear_latest_batch(); }};

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
        defer cleanup{[&]() { store.clear_latest_batch(); }};

        // An empty owned_object is not a map, so insert is a no-op;
        // latest_batch_ was already cleared by the previous clear_latest_batch().
        owned_object third = owned_object{};
        store.insert_and_apply(std::move(third));
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
        defer cleanup{[&]() { store.clear_latest_batch(); }};

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
        defer cleanup{[&]() { store.clear_latest_batch(); }};

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
        defer cleanup{[&]() { store.clear_latest_batch(); }};
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

    ctx_store.insert_and_apply(query, "query", test::ddwaf_object_da::make_string("hello"));

    EXPECT_FALSE(ctx_store.empty());
    EXPECT_TRUE(ctx_store.has_new_targets());
    EXPECT_TRUE(ctx_store.is_new_target(query));
    EXPECT_FALSE(ctx_store.is_new_target(url));
    EXPECT_TRUE(ctx_store.get_target(query).has_value());
    EXPECT_FALSE(ctx_store.get_target(url).has_value());

    {
        auto sctx_store = object_store::from_upstream_store(ctx_store);
        sctx_store.insert_and_apply(url, "url", test::ddwaf_object_da::make_string("hello"));

        EXPECT_FALSE(sctx_store.empty());
        EXPECT_TRUE(sctx_store.has_new_targets());
        EXPECT_TRUE(sctx_store.is_new_target(query));
        EXPECT_TRUE(sctx_store.is_new_target(url));
        EXPECT_TRUE(sctx_store.get_target(query).has_value());
        EXPECT_TRUE(sctx_store.get_target(url).has_value());
    }

    ctx_store.clear_latest_batch();

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
        defer cleanup{[&]() { ctx_store.clear_latest_batch(); }};

        ctx_store.insert_and_apply(query, "query", test::ddwaf_object_da::make_string("hello"));

        EXPECT_FALSE(ctx_store.empty());
        EXPECT_TRUE(ctx_store.has_new_targets());
        EXPECT_TRUE(ctx_store.is_new_target(query));
        EXPECT_FALSE(ctx_store.is_new_target(url));
        EXPECT_TRUE(ctx_store.get_target(query).has_value());
        EXPECT_FALSE(ctx_store.get_target(url).has_value());
    }

    {
        defer cleanup{[&]() { ctx_store.clear_latest_batch(); }};

        auto sctx_store = object_store::from_upstream_store(ctx_store);
        sctx_store.insert_and_apply(url, "url", test::ddwaf_object_da::make_string("hello"));

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
        defer cleanup{[&]() { store.clear_latest_batch(); }};

        EXPECT_TRUE(
            store.insert_and_apply(query, "query", test::ddwaf_object_da::make_string("hello")));

        EXPECT_FALSE(store.empty());
        EXPECT_TRUE(store.has_new_targets());
        EXPECT_TRUE(store.is_new_target(query));

        auto object = store.get_target(query);
        EXPECT_TRUE(object.has_value());
        EXPECT_STRV(object.as<std::string_view>(), "hello");
    }

    {
        defer cleanup{[&]() { store.clear_latest_batch(); }};

        EXPECT_TRUE(
            store.insert_and_apply(query, "query", test::ddwaf_object_da::make_string("bye")));

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
        defer cleanup{[&]() { store.clear_latest_batch(); }};
        {
            EXPECT_TRUE(store.insert_and_apply(
                query, "query", test::ddwaf_object_da::make_string("hello")));

            EXPECT_FALSE(store.empty());
            EXPECT_TRUE(store.has_new_targets());
            EXPECT_TRUE(store.is_new_target(query));

            auto object = store.get_target(query);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            EXPECT_TRUE(
                store.insert_and_apply(query, "query", test::ddwaf_object_da::make_string("bye")));

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
        defer cleanup{[&]() { ctx_store.clear_latest_batch(); }};
        {
            object_store sctx_store;
            EXPECT_TRUE(sctx_store.insert_and_apply(
                query, "query", test::ddwaf_object_da::make_string("hello")));

            EXPECT_FALSE(sctx_store.empty());
            EXPECT_TRUE(sctx_store.has_new_targets());
            EXPECT_TRUE(sctx_store.is_new_target(query));

            auto object = sctx_store.get_target(query);
            EXPECT_TRUE(object.has_value());
            EXPECT_STRV(object.as<std::string_view>(), "hello");
        }

        {
            EXPECT_TRUE(ctx_store.insert_and_apply(
                query, "query", test::ddwaf_object_da::make_string("bye")));

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
        defer cleanup{[&]() { ctx_store.clear_latest_batch(); }};
        {
            EXPECT_TRUE(ctx_store.insert_and_apply(
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
            EXPECT_TRUE(sctx_store.insert_and_apply(
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
        defer cleanup{[&]() { ctx_store.clear_latest_batch(); }};

        EXPECT_TRUE(ctx_store.insert_and_apply(
            query, "query", test::ddwaf_object_da::make_string("hello")));

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
            sctx_store.insert_and_apply(query, "query", test::ddwaf_object_da::make_string("bye")));

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

TEST(TestObjectStore, TargetSet)
{
    target_set set;
    EXPECT_TRUE(set.empty());
    EXPECT_FALSE(set.contains(0));
    EXPECT_FALSE(set.contains(1000));

    set.resize(130);
    EXPECT_TRUE(set.empty());
    for (target_index target : {129, 0, 64, 63, 1}) { set.insert(target); }
    EXPECT_FALSE(set.empty());
    EXPECT_TRUE(set.contains(0));
    EXPECT_TRUE(set.contains(129));
    EXPECT_FALSE(set.contains(2));
    EXPECT_FALSE(set.contains(1000));

    std::vector<target_index> targets;
    set.for_each([&](target_index target) { targets.emplace_back(target); });
    EXPECT_EQ(targets, (std::vector<target_index>{0, 1, 63, 64, 129}));

    set.clear();
    EXPECT_TRUE(set.empty());
    EXPECT_FALSE(set.contains(0));
    targets.clear();
    set.for_each([&](target_index target) { targets.emplace_back(target); });
    EXPECT_TRUE(targets.empty());
}

TEST(TestObjectStore, InsertWithLookup)
{
    auto query = get_target_index("object_store_test.lookup.query");
    auto lookup = get_target_lookup();
    // Registered after the lookup was created, so the store doesn't know it
    auto url = get_target_index("object_store_test.lookup.url");

    auto root = test::ddwaf_object_da::make_map();
    root.emplace("object_store_test.lookup.query", test::ddwaf_object_da::make_string("hello"));
    root.emplace("object_store_test.lookup.url", test::ddwaf_object_da::make_string("world"));
    root.emplace("object_store_test.lookup.unknown", test::ddwaf_object_da::make_string("!"));

    object_store store{lookup.get()};
    EXPECT_TRUE(store.empty());
    store.insert_and_apply(std::move(root));

    // Addresses unknown to the lookup are ignored
    EXPECT_FALSE(store.empty());
    EXPECT_TRUE(store.has_new_targets());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).has_value());
    EXPECT_FALSE(store.get_target(url).has_value());
    EXPECT_FALSE(store.get_target("object_store_test.lookup.unknown").has_value());
    EXPECT_TRUE(store.updated_targets().contains(query));
    EXPECT_FALSE(store.updated_targets().contains(url));

    // Derived targets are registered by index, regardless of the lookup
    store.insert_and_apply(
        url, "object_store_test.lookup.url", test::ddwaf_object_da::make_string("derived"));
    EXPECT_TRUE(store.is_new_target(url));
    EXPECT_STRV(store.get_target(url).as<std::string_view>(), "derived");

    auto sctx_store = object_store::from_upstream_store(store);
    EXPECT_TRUE(sctx_store.is_new_target(query));
    EXPECT_TRUE(sctx_store.is_new_target(url));

    store.clear_latest_batch();
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));
    EXPECT_TRUE(store.get_target(query).has_value());

    // The subcontext store derived from the batch, not the store
    EXPECT_TRUE(sctx_store.has_new_targets());
    EXPECT_TRUE(sctx_store.is_new_target(url));
    EXPECT_STRV(sctx_store.get_target(query).as<std::string_view>(), "hello");
}

TEST(TestObjectStore, ReplaceWithLookup)
{
    auto query = get_target_index("object_store_test.replace.query");
    auto lookup = get_target_lookup();

    object_store store{lookup.get()};
    {
        auto root = test::ddwaf_object_da::make_map();
        root.emplace("object_store_test.replace.query", test::ddwaf_object_da::make_string("1"));
        store.insert_and_apply(std::move(root));
    }
    store.clear_latest_batch();
    {
        auto root = test::ddwaf_object_da::make_map();
        root.emplace("object_store_test.replace.query", test::ddwaf_object_da::make_string("2"));
        store.insert_and_apply(std::move(root));
    }

    // The replacement is new and the previous object is still owned
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_STRV(store.get_target(query).as<std::string_view>(), "2");
    EXPECT_TRUE(store.updated_targets().contains(query));
    store.clear_updated_targets();
    EXPECT_TRUE(store.updated_targets().empty());
    EXPECT_FALSE(store.updated_targets().contains(query));
    EXPECT_TRUE(store.is_new_target(query));
}

} // namespace
