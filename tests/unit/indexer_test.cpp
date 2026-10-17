// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "indexer.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

template <typename T> bool contains(const std::vector<T *> &items, T *item)
{
    return std::find(items.begin(), items.end(), item) != items.end();
}

struct test_object {
    test_object(std::string id_, std::unordered_map<std::string, std::string> tags_)
        : id(std::move(id_)), tags(std::move(tags_))
    {}

    std::string_view get_id() const { return id; }
    const std::unordered_map<std::string, std::string> &get_tags() const { return tags; }

    std::string id;
    std::unordered_map<std::string, std::string> tags;
};

TEST(TestIndexer, FindSingleElement)
{
    indexer<test_object> index;
    auto object =
        std::make_shared<test_object>("id", decltype(test_object::tags){{"tag", "value"}});
    index.emplace(object.get());
    EXPECT_EQ(index.size(), 1);

    EXPECT_TRUE(index.contains("id"));
    EXPECT_EQ(index.find_by_id("id"), object.get());

    auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value"}});
    EXPECT_EQ(items.size(), 1);
    EXPECT_TRUE(contains(items, object.get()));
}

/*TEST(TestIndexer, EraseSingleElementById)*/
/*{*/
/*indexer<test_object> index;*/
/*auto object =*/
/*std::make_shared<test_object>("id", decltype(test_object::tags){{"tag", "value"}});*/
/*index.emplace(object.get());*/
/*EXPECT_EQ(index.size(), 1);*/

/*index.erase("id");*/
/*EXPECT_EQ(index.size(), 0);*/

/*EXPECT_FALSE(index.contains("id"));*/
/*EXPECT_EQ(index.find_by_id("id"), nullptr);*/

/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value"}});*/
/*EXPECT_TRUE(items.empty());*/
/*}*/

/*TEST(TestIndexer, EraseSingleElementByIterator)*/
/*{*/
/*indexer<test_object> index;*/
/*auto object =*/
/*std::make_shared<test_object>("id", decltype(test_object::tags){{"tag", "value"}});*/
/*index.emplace(object);*/
/*EXPECT_EQ(index.size(), 1);*/

/*auto it = index.begin();*/
/*index.erase(it);*/
/*EXPECT_EQ(index.size(), 0);*/

/*EXPECT_FALSE(index.contains("id"));*/
/*EXPECT_EQ(index.find_by_id("id"), nullptr);*/

/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value"}});*/
/*EXPECT_TRUE(items.empty());*/
/*}*/

TEST(TestIndexer, ClearSingleElement)
{
    indexer<test_object> index;
    auto object =
        std::make_shared<test_object>("id", decltype(test_object::tags){{"tag", "value"}});
    index.emplace(object.get());
    EXPECT_EQ(index.size(), 1);

    index.clear();
    EXPECT_EQ(index.size(), 0);

    EXPECT_FALSE(index.contains("id"));
    EXPECT_EQ(index.find_by_id("id"), nullptr);

    auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value"}});
    EXPECT_TRUE(items.empty());
}

TEST(TestIndexer, IterateSingleElement)
{
    indexer<test_object> index;
    auto object =
        std::make_shared<test_object>("id", decltype(test_object::tags){{"tag", "value"}});
    index.emplace(object.get());
    EXPECT_EQ(index.size(), 1);

    for (const auto &[id, value] : index) { EXPECT_EQ(value, object.get()); }
}

TEST(TestIndexer, FindMultipleElements)
{
    indexer<test_object> index;
    std::unordered_map<std::string, std::shared_ptr<test_object>> objects{
        {"id0", std::make_shared<test_object>(
                    "id0", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},
        {"id1", std::make_shared<test_object>(
                    "id1", decltype(test_object::tags){{"tag", "value2"}, {"common", "value"}})},
        {"id2", std::make_shared<test_object>(
                    "id2", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},
        {"id3",
            std::make_shared<test_object>("id3", decltype(test_object::tags){{"tag", "value2"},
                                                     {"common", "value"}, {"random", "value"}})},
    };

    for (const auto &[id, o] : objects) { index.emplace(o.get()); }

    EXPECT_EQ(index.size(), 4);

    EXPECT_TRUE(index.contains("id0"));
    EXPECT_TRUE(index.contains("id1"));
    EXPECT_TRUE(index.contains("id2"));
    EXPECT_TRUE(index.contains("id3"));

    EXPECT_EQ(index.find_by_id("id0"), objects["id0"].get());
    EXPECT_EQ(index.find_by_id("id1"), objects["id1"].get());
    EXPECT_EQ(index.find_by_id("id2"), objects["id2"].get());
    EXPECT_EQ(index.find_by_id("id3"), objects["id3"].get());

    {
        auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value1"}});
        EXPECT_EQ(items.size(), 2);
        EXPECT_TRUE(contains(items, objects["id0"].get()));
        EXPECT_TRUE(contains(items, objects["id2"].get()));
    }

    {
        auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});
        EXPECT_EQ(items.size(), 2);
        EXPECT_TRUE(contains(items, objects["id1"].get()));
        EXPECT_TRUE(contains(items, objects["id3"].get()));
    }

    {
        auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});
        EXPECT_EQ(items.size(), 4);
        EXPECT_TRUE(contains(items, objects["id0"].get()));
        EXPECT_TRUE(contains(items, objects["id1"].get()));
        EXPECT_TRUE(contains(items, objects["id2"].get()));
        EXPECT_TRUE(contains(items, objects["id3"].get()));
    }

    {
        auto items = index.find_by_tags(decltype(test_object::tags){{"random", "value"}});
        EXPECT_EQ(items.size(), 1);
        EXPECT_TRUE(contains(items, objects["id3"].get()));
    }
}

/*TEST(TestIndexer, EraseMultipleElementsById)*/
/*{*/
/*indexer<test_object> index;*/
/*std::unordered_map<std::string, std::shared_ptr<test_object>> objects{*/
/*{"id0", std::make_shared<test_object>(*/
/*"id0", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},*/
/*{"id1", std::make_shared<test_object>(*/
/*"id1", decltype(test_object::tags){{"tag", "value2"}, {"common", "value"}})},*/
/*{"id2", std::make_shared<test_object>(*/
/*"id2", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},*/
/*{"id3",*/
/*std::make_shared<test_object>("id3", decltype(test_object::tags){{"tag", "value2"},*/
/*{"common", "value"}, {"random", "value"}})},*/
/*};*/

/*for (const auto &[id, o] : objects) { index.emplace(o); }*/

/*EXPECT_EQ(index.size(), 4);*/

/*index.erase("id0");*/
/*EXPECT_EQ(index.size(), 3);*/

/*EXPECT_FALSE(index.contains("id0"));*/
/*EXPECT_TRUE(index.contains("id1"));*/
/*EXPECT_TRUE(index.contains("id2"));*/
/*EXPECT_TRUE(index.contains("id3"));*/

/*EXPECT_EQ(index.find_by_id("id1"), objects["id1"].get());*/
/*EXPECT_EQ(index.find_by_id("id2"), objects["id2"].get());*/
/*EXPECT_EQ(index.find_by_id("id3"), objects["id3"].get());*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value1"}});*/
/*EXPECT_EQ(items.size(), 1);*/
/*EXPECT_TRUE(items.contains(objects["id2"].get()));*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});*/
/*EXPECT_EQ(items.size(), 2);*/
/*EXPECT_TRUE(items.contains(objects["id1"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});*/
/*EXPECT_EQ(items.size(), 3);*/
/*EXPECT_TRUE(items.contains(objects["id1"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id2"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*index.erase("id2");*/
/*EXPECT_EQ(index.size(), 2);*/

/*EXPECT_FALSE(index.contains("id0"));*/
/*EXPECT_TRUE(index.contains("id1"));*/
/*EXPECT_FALSE(index.contains("id2"));*/
/*EXPECT_TRUE(index.contains("id3"));*/

/*EXPECT_EQ(index.find_by_id("id1"), objects["id1"].get());*/
/*EXPECT_EQ(index.find_by_id("id3"), objects["id3"].get());*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value1"}});*/
/*EXPECT_EQ(items.size(), 0);*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});*/
/*EXPECT_EQ(items.size(), 2);*/
/*EXPECT_TRUE(items.contains(objects["id1"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});*/
/*EXPECT_EQ(items.size(), 2);*/
/*EXPECT_TRUE(items.contains(objects["id1"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*index.erase("id1");*/
/*EXPECT_EQ(index.size(), 1);*/

/*EXPECT_FALSE(index.contains("id0"));*/
/*EXPECT_FALSE(index.contains("id1"));*/
/*EXPECT_FALSE(index.contains("id2"));*/
/*EXPECT_TRUE(index.contains("id3"));*/

/*EXPECT_EQ(index.find_by_id("id3"), objects["id3"].get());*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});*/
/*EXPECT_EQ(items.size(), 1);*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});*/
/*EXPECT_EQ(items.size(), 1);*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*index.erase("id3");*/
/*EXPECT_EQ(index.size(), 0);*/

/*EXPECT_FALSE(index.contains("id0"));*/
/*EXPECT_FALSE(index.contains("id1"));*/
/*EXPECT_FALSE(index.contains("id2"));*/
/*EXPECT_FALSE(index.contains("id3"));*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});*/
/*EXPECT_EQ(items.size(), 0);*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});*/
/*EXPECT_EQ(items.size(), 0);*/
/*}*/
/*}*/

/*TEST(TestIndexer, EraseMultipleElementsByIterator)*/
/*{*/
/*indexer<test_object> index;*/
/*std::unordered_map<std::string, std::shared_ptr<test_object>> objects{*/
/*{"id0", std::make_shared<test_object>(*/
/*"id0", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},*/
/*{"id1", std::make_shared<test_object>(*/
/*"id1", decltype(test_object::tags){{"tag", "value2"}, {"common", "value"}})},*/
/*{"id2", std::make_shared<test_object>(*/
/*"id2", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},*/
/*{"id3",*/
/*std::make_shared<test_object>("id3", decltype(test_object::tags){{"tag", "value2"},*/
/*{"common", "value"}, {"random", "value"}})},*/
/*};*/

/*for (const auto &[id, o] : objects) { index.emplace(o); }*/

/*EXPECT_EQ(index.size(), 4);*/

/*auto find_iterator = [&index](std::string_view id) {*/
/*for (auto it = index.begin(); it != index.end(); ++it) {*/
/*if ((*it)->get_id() == id) {*/
/*return it;*/
/*}*/
/*}*/
/*return index.end();*/
/*};*/

/*{*/
/*auto it = find_iterator("id0");*/
/*index.erase(it);*/
/*}*/
/*EXPECT_EQ(index.size(), 3);*/

/*EXPECT_FALSE(index.contains("id0"));*/
/*EXPECT_TRUE(index.contains("id1"));*/
/*EXPECT_TRUE(index.contains("id2"));*/
/*EXPECT_TRUE(index.contains("id3"));*/

/*EXPECT_EQ(index.find_by_id("id1"), objects["id1"].get());*/
/*EXPECT_EQ(index.find_by_id("id2"), objects["id2"].get());*/
/*EXPECT_EQ(index.find_by_id("id3"), objects["id3"].get());*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value1"}});*/
/*EXPECT_EQ(items.size(), 1);*/
/*EXPECT_TRUE(items.contains(objects["id2"].get()));*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});*/
/*EXPECT_EQ(items.size(), 2);*/
/*EXPECT_TRUE(items.contains(objects["id1"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});*/
/*EXPECT_EQ(items.size(), 3);*/
/*EXPECT_TRUE(items.contains(objects["id1"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id2"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*{*/
/*auto it = find_iterator("id2");*/
/*index.erase(it);*/
/*}*/
/*EXPECT_EQ(index.size(), 2);*/

/*EXPECT_FALSE(index.contains("id0"));*/
/*EXPECT_TRUE(index.contains("id1"));*/
/*EXPECT_FALSE(index.contains("id2"));*/
/*EXPECT_TRUE(index.contains("id3"));*/

/*EXPECT_EQ(index.find_by_id("id1"), objects["id1"].get());*/
/*EXPECT_EQ(index.find_by_id("id3"), objects["id3"].get());*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value1"}});*/
/*EXPECT_EQ(items.size(), 0);*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});*/
/*EXPECT_EQ(items.size(), 2);*/
/*EXPECT_TRUE(items.contains(objects["id1"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});*/
/*EXPECT_EQ(items.size(), 2);*/
/*EXPECT_TRUE(items.contains(objects["id1"].get()));*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*{*/
/*auto it = find_iterator("id1");*/
/*index.erase(it);*/
/*}*/
/*EXPECT_EQ(index.size(), 1);*/

/*EXPECT_FALSE(index.contains("id0"));*/
/*EXPECT_FALSE(index.contains("id1"));*/
/*EXPECT_FALSE(index.contains("id2"));*/
/*EXPECT_TRUE(index.contains("id3"));*/

/*EXPECT_EQ(index.find_by_id("id3"), objects["id3"].get());*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});*/
/*EXPECT_EQ(items.size(), 1);*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});*/
/*EXPECT_EQ(items.size(), 1);*/
/*EXPECT_TRUE(items.contains(objects["id3"].get()));*/
/*}*/

/*{*/
/*auto it = find_iterator("id3");*/
/*index.erase(it);*/
/*}*/
/*EXPECT_EQ(index.size(), 0);*/

/*EXPECT_FALSE(index.contains("id0"));*/
/*EXPECT_FALSE(index.contains("id1"));*/
/*EXPECT_FALSE(index.contains("id2"));*/
/*EXPECT_FALSE(index.contains("id3"));*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});*/
/*EXPECT_EQ(items.size(), 0);*/
/*}*/

/*{*/
/*auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});*/
/*EXPECT_EQ(items.size(), 0);*/
/*}*/
/*}*/

TEST(TestIndexer, ClearMultipleElements)
{
    indexer<test_object> index;
    std::unordered_map<std::string, std::shared_ptr<test_object>> objects{
        {"id0", std::make_shared<test_object>(
                    "id0", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},
        {"id1", std::make_shared<test_object>(
                    "id1", decltype(test_object::tags){{"tag", "value2"}, {"common", "value"}})},
        {"id2", std::make_shared<test_object>(
                    "id2", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},
        {"id3",
            std::make_shared<test_object>("id3", decltype(test_object::tags){{"tag", "value2"},
                                                     {"common", "value"}, {"random", "value"}})},
    };

    for (const auto &[id, o] : objects) { index.emplace(o.get()); }

    EXPECT_EQ(index.size(), 4);

    index.clear();
    EXPECT_EQ(index.size(), 0);

    EXPECT_FALSE(index.contains("id0"));
    EXPECT_FALSE(index.contains("id1"));
    EXPECT_FALSE(index.contains("id2"));
    EXPECT_FALSE(index.contains("id3"));

    {
        auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value1"}});
        EXPECT_EQ(items.size(), 0);
    }

    {
        auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value2"}});
        EXPECT_EQ(items.size(), 0);
    }

    {
        auto items = index.find_by_tags(decltype(test_object::tags){{"common", "value"}});
        EXPECT_EQ(items.size(), 0);
    }
}

TEST(TestIndexer, IterateMultipleElements)
{
    indexer<test_object> index;
    std::unordered_map<std::string, std::shared_ptr<test_object>> objects{
        {"id0", std::make_shared<test_object>(
                    "id0", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},
        {"id1", std::make_shared<test_object>(
                    "id1", decltype(test_object::tags){{"tag", "value2"}, {"common", "value"}})},
        {"id2", std::make_shared<test_object>(
                    "id2", decltype(test_object::tags){{"tag", "value1"}, {"common", "value"}})},
        {"id3",
            std::make_shared<test_object>("id3", decltype(test_object::tags){{"tag", "value2"},
                                                     {"common", "value"}, {"random", "value"}})},
    };

    for (const auto &[id, o] : objects) { index.emplace(o.get()); }

    EXPECT_EQ(index.size(), 4);

    for (const auto &[id, item] : index) {
        auto it = objects.find(std::string{item->get_id()});
        EXPECT_NE(it, objects.end());
        objects.erase(it);
    }
    EXPECT_TRUE(objects.empty());
}

/*TEST(TestIndexer, EraseNonExistentKey)*/
/*{*/
/*indexer<test_object> index;*/
/*auto object =*/
/*std::make_shared<test_object>("id", decltype(test_object::tags){{"tag", "value"}});*/
/*index.emplace(object);*/
/*EXPECT_EQ(index.size(), 1);*/

/*index.erase("random_id");*/
/*EXPECT_EQ(index.size(), 1);*/

/*EXPECT_TRUE(index.contains("id"));*/
/*EXPECT_EQ(index.find_by_id("id"), object.get());*/

/*auto items = index.find_by_tags(decltype(test_object::tags){{"tag", "value"}});*/
/*EXPECT_EQ(items.size(), 1);*/
/*EXPECT_TRUE(items.contains(object.get()));*/
/*}*/

} // namespace

namespace {

TEST(TestIndexer, ItemsAreSortedAndUnique)
{
    // Insert in an order unrelated to the addresses
    std::vector<test_object> storage;
    storage.reserve(8);
    for (unsigned i = 0; i < 8; ++i) {
        storage.emplace_back(
            "id" + std::to_string(i), decltype(test_object::tags){{"tag", "value"}});
    }

    indexer<test_object> index;
    for (unsigned i : {5U, 1U, 7U, 0U, 3U, 6U, 2U, 4U}) { index.emplace(&storage[i]); }

    // A second item with an existing ID is not indexed by ID, but is by tags
    test_object duplicate{"id3", decltype(test_object::tags){{"tag", "value"}}};
    index.emplace(&duplicate);

    const auto &items = index.items();
    ASSERT_EQ(items.size(), 8);
    EXPECT_TRUE(std::is_sorted(items.begin(), items.end(), std::less<test_object *>{}));
    EXPECT_FALSE(contains(items, &duplicate));
    for (auto &object : storage) { EXPECT_TRUE(contains(items, &object)); }

    auto tagged = index.find_by_tags(decltype(test_object::tags){{"tag", "value"}});
    EXPECT_EQ(tagged.size(), 9);
    EXPECT_TRUE(std::is_sorted(tagged.begin(), tagged.end(), std::less<test_object *>{}));
    EXPECT_TRUE(contains(tagged, &duplicate));

    index.clear();
    EXPECT_TRUE(index.items().empty());
}

} // namespace
