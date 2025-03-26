// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "exception.hpp"
#include "exclusion/object_filter.hpp"

using namespace ddwaf;
using namespace ddwaf::exclusion;
using namespace std::literals;

namespace {
TEST(TestObjectFilter, RootTarget)
{
    auto query = get_target_index("query");

    object_store store;

    auto root = owned_object::make_map({
        {"query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}})},
    });
    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, false, deadline);

    ASSERT_EQ(objects_filtered.size(), 1);
    EXPECT_TRUE(objects_filtered.contains(root.at(0)));
}

TEST(TestObjectFilter, DuplicateTarget)
{
    auto query = get_target_index("query");

    object_store store;

    object_filter filter;
    filter.insert(query, "query", {});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;

    std::vector<owned_object> objects;
    objects.emplace_back(owned_object::make_map({
        {"query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}})},
    }));
    objects.emplace_back(owned_object::make_map({
        {"query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}})},
    }));
    {
        store.insert(objects[0]);

        auto objects_filtered = filter.match(store, cache, false, deadline);

        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(objects[0].at(0)));
    }

    {
        store.insert(objects[1]);

        auto objects_filtered = filter.match(store, cache, false, deadline);

        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(objects[1].at(0)));
    }
}

TEST(TestObjectFilter, DuplicateCachedTarget)
{
    auto query = get_target_index("query");

    object_store store;

    object_filter filter;
    filter.insert(query, "query", {});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;

    auto root = owned_object::make_map({
        {"query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}})},
    });
    store.insert(root);

    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(root.at(0)));
    }

    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, SingleTarget)
{
    auto query = get_target_index("query");

    object_store store;

    auto root = owned_object::make_map();
    auto child = root.emplace(
        "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {"params"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, false, deadline);

    ASSERT_EQ(objects_filtered.size(), 1);
    EXPECT_TRUE(objects_filtered.contains(child.at(0)));
}

TEST(TestObjectFilter, DuplicateSingleTarget)
{
    auto query = get_target_index("query");

    object_store store;

    object_filter filter;
    filter.insert(query, "query", {"params"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;

    {
        auto root = owned_object::make_map();
        auto child = root.emplace(
            "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

        store.insert(std::move(root));

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(child.at(0)));
    }

    {
        auto root = owned_object::make_map();
        auto child = root.emplace(
            "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

        store.insert(std::move(root));

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(child.at(0)));
    }
}

TEST(TestObjectFilter, MultipleTargets)
{
    auto query = get_target_index("query");
    auto path_params = get_target_index("path_params");

    object_store store;

    auto root = owned_object::make_map();

    // Query
    auto child = root.emplace(
        "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

    // Path Params
    auto sibling = root.emplace("path_params", owned_object::make_map({{"username", "Paco"}}));

    auto object = sibling.emplace(
        "token", owned_object::make_map({{"value", "naskjdnakjsd"}, {"expiration", "yesterday"}}));

    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {"uri"});
    filter.insert(path_params, "path_params", {"token", "value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, false, deadline);

    ASSERT_EQ(objects_filtered.size(), 2);
    EXPECT_TRUE(objects_filtered.contains(child.at(1)));
    EXPECT_TRUE(objects_filtered.contains(object.at(0)));
}

TEST(TestObjectFilter, DuplicateMultipleTargets)
{
    auto query = get_target_index("query");
    auto path_params = get_target_index("path_params");

    object_store store;

    object_filter filter;
    filter.insert(query, "query", {"uri"});
    filter.insert(path_params, "path_params", {"token", "value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;

    {
        auto root = owned_object::make_map();
        // Query
        auto child = root.emplace(
            "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

        // Path Params
        auto sibling = root.emplace("path_params", owned_object::make_map({{"username", "Paco"}}));

        auto object = sibling.emplace("token",
            owned_object::make_map({{"value", "naskjdnakjsd"}, {"expiration", "yesterday"}}));

        store.insert(std::move(root));

        auto objects_filtered = filter.match(store, cache, false, deadline);

        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(child.at(1)));
        EXPECT_TRUE(objects_filtered.contains(object.at(0)));
    }

    {
        auto root = owned_object::make_map();
        // Query
        auto child = root.emplace(
            "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

        // Path Params
        auto sibling = root.emplace("path_params", owned_object::make_map({{"username", "Paco"}}));

        auto object = sibling.emplace("token",
            owned_object::make_map({{"value", "naskjdnakjsd"}, {"expiration", "yesterday"}}));

        store.insert(std::move(root));

        auto objects_filtered = filter.match(store, cache, false, deadline);

        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(child.at(1)));
        EXPECT_TRUE(objects_filtered.contains(object.at(0)));
    }
}

TEST(TestObjectFilter, MissingTarget)
{
    get_target_index("query");
    get_target_index("path_params");
    auto status = get_target_index("status");

    object_store store;

    auto root = owned_object::make_map({
        {"query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}})},
        {"path_params", owned_object::make_map({{"username", "Paco"},
                            {"token", owned_object::make_map({{"value", "naskjdnakjsd"},
                                          {"expiration", "yesterday"}})}})},
    });
    store.insert(root);

    object_filter filter;
    filter.insert(status, "status", {"value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    auto objects_filtered = filter.match(store, cache, false, deadline);
    ASSERT_EQ(objects_filtered.size(), 0);
}

TEST(TestObjectFilter, SingleTargetCache)
{
    auto query = get_target_index("query");

    object_store store;

    auto root = owned_object::make_map();
    auto child = root.emplace(
        "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {"params"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(child.at(0)));
    }

    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        EXPECT_TRUE(objects_filtered.empty());
    }
}

TEST(TestObjectFilter, MultipleTargetsCache)
{
    auto query = get_target_index("query");
    auto path_params = get_target_index("path_params");

    object_store store;

    object_filter filter;
    filter.insert(query, "query", {"uri"});
    filter.insert(path_params, "path_params", {"token", "value"});

    ddwaf::timer deadline{2s};
    object_filter::cache_type cache;
    {
        auto root = owned_object::make_map();
        auto child = root.emplace(
            "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

        store.insert(std::move(root));

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(child.at(1)));
    }

    {
        auto root = owned_object::make_map();
        // Path Params
        auto sibling = root.emplace("path_params", owned_object::make_map({{"username", "Paco"}}));

        auto object = sibling.emplace("token",
            owned_object::make_map({{"value", "naskjdnakjsd"}, {"expiration", "yesterday"}}));

        store.insert(std::move(root));

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(object.at(0)));
    }

    {
        auto objects_filtered = filter.match(store, cache, false, deadline);
        EXPECT_TRUE(objects_filtered.empty());
    }
}

TEST(TestObjectFilter, SingleGlobTarget)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"*"});

    ddwaf::timer deadline{2s};
    {
        object_store store;
        object_filter::cache_type cache;
        auto root = owned_object::make_map();
        auto child = root.emplace(
            "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(child.at(0)));
        EXPECT_TRUE(objects_filtered.contains(child.at(1)));
    }

    {
        object_store store;
        object_filter::cache_type cache;

        auto root = owned_object::make_map();
        auto child = root.emplace("query",
            owned_object::make_map({{"params", owned_object::make_map({{"value", "paramsvalue"}})},
                {"uri", "uri_value"}}));

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(child.at(0)));
        EXPECT_TRUE(objects_filtered.contains(child.at(1)));
    }

    {
        object_store store;
        object_filter::cache_type cache;

        auto root = owned_object::make_map({{"query", owned_object{}}});
        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, GlobAndKeyTarget)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"*"});
    filter.insert(query, "query", {"uri"});

    ddwaf::timer deadline{2s};
    {
        object_store store;
        object_filter::cache_type cache;

        auto root = owned_object::make_map();
        auto child = root.emplace(
            "query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}}));

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(child.at(0)));
        EXPECT_TRUE(objects_filtered.contains(child.at(1)));
    }

    {
        object_store store;
        object_filter::cache_type cache;

        auto root = owned_object::make_map();
        auto child = root.emplace("query",
            owned_object::make_map({{"params", owned_object::make_map({{"value", "paramsvalue"}})},
                {"uri", "uri_value"}}));

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(child.at(0)));
        EXPECT_TRUE(objects_filtered.contains(child.at(1)));
    }

    {
        object_store store;
        object_filter::cache_type cache;

        auto root = owned_object::make_map({{"query", owned_object{}}});
        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, MultipleComponentsGlobAndKeyTargets)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"*", "value"});
    filter.insert(query, "query", {"uri", "other"});

    ddwaf::timer deadline{2s};

    {
        object_store store;
        object_filter::cache_type cache;

        owned_object root = owned_object::make_map();
        auto child = root.emplace(
            "query", owned_object::make_map(
                         {{"params", owned_object::make_map({{"other", "paramsvalue"}})}}));
        auto grandnephew = child.emplace("uri", owned_object::make_map({{"other", "paramsvalue"}}));

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
        EXPECT_TRUE(objects_filtered.contains(grandnephew.at(0)));
    }

    {
        object_store store;
        object_filter::cache_type cache;

        owned_object root = owned_object::make_map();
        auto child = root.emplace("query", owned_object::make_map());
        auto grandchild =
            child.emplace("params", owned_object::make_map({{"value", "paramsvalue"}}));
        auto grandnephew = child.emplace("uri", owned_object::make_map({{"value", "paramsvalue"}}));

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 2);
        EXPECT_TRUE(objects_filtered.contains(grandnephew.at(0)));
        EXPECT_TRUE(objects_filtered.contains(grandchild.at(0)));
    }

    {
        object_store store;
        object_filter::cache_type cache;
        owned_object root = owned_object::make_map(
            {{"query", owned_object::make_map(
                           {{"value", owned_object::make_map({{"whatever", "paramsvalue"}})},
                               {"other", owned_object::make_map({{"random", "paramsvalue"}})}})}});

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }

    {
        object_store store;
        object_filter::cache_type cache;

        owned_object root =
            owned_object::make_map({{"query", owned_object::make_map({{"value", "value"}})}});

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, MultipleGlobsTargets)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"*", "*", "*"});

    ddwaf::timer deadline{2s};

    {
        object_store store;
        object_filter::cache_type cache;

        owned_object root = owned_object::make_map();
        auto child = root.emplace("query", owned_object::make_map());
        auto grandchild = child.emplace("params", owned_object::make_map());
        auto greatgrandchild = grandchild.emplace("something",
            owned_object::make_map({{"other", "paramsvalue"}, {"somethingelse", "paramsvalue"}}));
        auto grandnephew = child.emplace("uri", owned_object::make_map());
        auto greatgrandnephew = grandnephew.emplace("random",
            owned_object::make_map({{"other", "paramsvalue"}, {"somethingelse", "paramsvalue"}}));

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 4);
        EXPECT_TRUE(objects_filtered.contains(greatgrandchild.at(0)));
        EXPECT_TRUE(objects_filtered.contains(greatgrandchild.at(1)));
        EXPECT_TRUE(objects_filtered.contains(greatgrandnephew.at(0)));
        EXPECT_TRUE(objects_filtered.contains(greatgrandnephew.at(1)));
    }

    {
        object_store store;
        object_filter::cache_type cache;

        auto root = owned_object::make_map({{"query",
            owned_object::make_map({{"params", owned_object::make_map({{"something", "value"}})},
                {"uri", owned_object::make_map({{"random", "value"}})}})}});

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }

    {
        object_store store;
        object_filter::cache_type cache;

        auto root = owned_object::make_map(
            {{"query", owned_object::make_map({{"params", "value"}, {"uri", "value"}})}});

        store.insert(root);

        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 0);
    }
}

TEST(TestObjectFilter, MultipleComponentsMultipleGlobAndKeyTargets)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"a", "b", "c"});
    filter.insert(query, "query", {"a", "*", "d", "e"});
    filter.insert(query, "query", {"a", "*", "e", "*"});
    filter.insert(query, "query", {"a", "*", "f", "*", "g"});

    // Successful tests
    {
        std::vector<std::pair<std::string, std::string>> tests{
            {"{query: {a: {b: {c: hello}}}}", "c"},
            {"{query: {a: {b: {c: {e: hello}}}}}", "c"},
            {"{query: {a: {b: {d: {e: hello}}}}}", "e"},
            {"{query: {a: {h: {d: {e: hello}}}}}", "e"},
            {"{query: {a: {g: {d: {e: {f: [hello, bye]}}}}}}", "e"},
            {"{query: {a: {n: {e: {f: [hello, bye]}}}}}", "f"},
            {"{query: {a: {n: {e: {x: [hello, bye]}}}}}", "x"},
            {"{query: {a: {n: {e: {x: {f: [hello, bye]}}}}}}", "x"},
            {"{query: {a: {p: {f: {x: {g: [hello, bye]}}}}}}", "g"},
            {"{query: {a: {a: {f: {e: {g: {k: [hello, bye]}}}}}}}", "g"},
        };

        for (auto &[object, result] : tests) {
            object_store store;
            object_filter::cache_type cache;
            auto root = yaml_to_object<owned_object>(object);
            store.insert(root);

            ddwaf::timer deadline{2s};
            auto objects_filtered = filter.match(store, cache, false, deadline);
            ASSERT_EQ(objects_filtered.size(), 1);
            // TODO Replace this test
            // EXPECT_STREQ((*objects_filtered.persistent.begin())->parameterName, result.c_str());
        }
    }

    // Failure tests
    {
        std::vector<std::string> tests{
            "{query: [a, b, c, d]}",
            "{query: hello}",
            "{query: {a: hello}}",
            "{query: {a: {b: hello}}}",
            "{query: {a: {b: {e: hello}}}}",
            "{query: {a: {b: [c]}}}",
            "{query: {a: {b: {g: {e: hello}}}}}",
            "{query: {a: {b: {f: {e: {h: hello}}}}}}",
        };

        for (auto &object : tests) {
            object_store store;
            object_filter::cache_type cache;
            auto root = yaml_to_object<owned_object>(object);
            store.insert(root);

            ddwaf::timer deadline{2s};
            auto objects_filtered = filter.match(store, cache, false, deadline);
            ASSERT_EQ(objects_filtered.size(), 0);
        }
    }
}

TEST(TestObjectFilter, ArrayWithGlobTargets)
{
    auto query = get_target_index("query");

    object_filter filter;
    filter.insert(query, "query", {"a", "*", "c", "d"});

    {
        object_store store;
        object_filter::cache_type cache;
        auto root = owned_object::make_map({{"query",
            owned_object::make_map({{"a", owned_object::make_array({owned_object::make_map({{"c",
                                              owned_object::make_map({{"d", "value"}})}})})}})}});

        store.insert(root);

        ddwaf::timer deadline{2s};
        auto objects_filtered = filter.match(store, cache, false, deadline);
        ASSERT_EQ(objects_filtered.size(), 1);
    }
}

TEST(TestObjectFilter, Timeout)
{
    auto query = get_target_index("query");

    object_store store;

    auto root = owned_object::make_map(
        {{"query", owned_object::make_map({{"params", "paramsvalue"}, {"uri", "uri_value"}})}});
    store.insert(root);

    object_filter filter;
    filter.insert(query, "query", {});

    ddwaf::timer deadline{0s};
    object_filter::cache_type cache;
    EXPECT_THROW(filter.match(store, cache, false, deadline), ddwaf::timeout_exception);
}

} // namespace
