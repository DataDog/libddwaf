// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "context_allocator.hpp"
#include "iterator.hpp"

using namespace ddwaf;

namespace {

TEST(TestValueIterator, TestInvalidIterator)
{
    owned_object object;

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_FALSE(it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestStringScalar)
{
    owned_object object{"value"};

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_EQ(*it, object_view{object});

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestUnsignedScalar)
{
    owned_object object{22U};

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_EQ(*it, object_view{object});

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestSignedScalar)
{
    owned_object object{22L};

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_EQ(*it, object_view{object});

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestArraySingleItem)
{
    auto object = owned_object::make_array({"string"});

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_STREQ((*it).as<const char *>(), "string");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "0");

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestArrayMultipleItems)
{
    auto object = owned_object::make_array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(std::to_string(i)); }

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);

    unsigned index = 0;
    do {
        auto index_str = std::to_string(index);
        EXPECT_TRUE(it);
        EXPECT_STREQ((*it).as<const char *>(), index_str.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), index_str.c_str());
        ++index;
    } while (++it);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestArrayMultipleNullAndInvalid)
{
    auto object = owned_object::make_array();
    for (unsigned i = 0; i < 25; i++) {
        object.emplace_back(std::to_string(i));
        object.emplace_back(owned_object{});
        object.emplace_back(nullptr);
    }

    EXPECT_EQ(object.size(), 75);

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);

    // Null and invalid objects should be skipped
    unsigned index = 0;
    do {
        EXPECT_TRUE(it);
        EXPECT_STREQ((*it).as<const char *>(), std::to_string(index).c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), std::to_string(index * 3).c_str());
        ++index;
    } while (++it);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestDeepArray)
{
    auto object = owned_object::make_array();
    borrowed_object array{object};
    for (unsigned i = 0; i < 10; i++) {
        array.emplace_back("val" + std::to_string(i));
        array = array.emplace_back(owned_object::make_array());
    }

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);
    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_STREQ((*it).as<const char *>(), ("val" + index).c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), i + 1);

        for (unsigned j = 0; j < i; j++) { EXPECT_STREQ(path[j].c_str(), "1"); }
        ++it;
    }

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestArrayNoScalars)
{
    auto object = owned_object::make_array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(owned_object::make_array()); }

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);

    EXPECT_FALSE(it);
    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestMapSingleItem)
{
    auto object = owned_object::make_map({{"key", "value"}});

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);

    EXPECT_TRUE(it);
    EXPECT_STREQ((*it).as<const char *>(), "value");
    EXPECT_STREQ((*it).ptr()->parameterName, "key");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "key");

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestMapMultipleItems)
{
    auto object = owned_object::make_map();

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        object.emplace("key" + index, "value" + index);
    }

    std::unordered_set<object_view> persistent{};
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;

        EXPECT_TRUE(it);
        EXPECT_STREQ((*it).as<const char *>(), value.c_str());
        EXPECT_STREQ((*it).ptr()->parameterName, key.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), key.c_str());
        ++it;
    }

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestMapMultipleMultipleNullAndInvalid)
{
    auto object = owned_object::make_map();

    for (unsigned i = 0; i < 25; i++) {
        {
            auto index = std::to_string(i * 3);
            object.emplace("key" + index, "value" + index);
        }

        {
            auto index = std::to_string(i * 3 + 1);
            object.emplace("key" + index, nullptr);
        }

        {
            auto index = std::to_string(i * 3 + 2);
            object.emplace("key" + index, owned_object{});
        }
    }

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 25; i++) {
        auto index = std::to_string(i * 3);
        std::string key = "key" + index;
        std::string value = "value" + index;

        EXPECT_TRUE(it);
        EXPECT_STREQ((*it).as<const char *>(), value.c_str());
        EXPECT_STREQ((*it).ptr()->parameterName, key.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), key.c_str());
        ++it;
    }

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestDeepMap)
{
    auto object = owned_object::make_map();
    borrowed_object map{object};

    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);
        map.emplace("str" + index, "val" + index);
        map = map.emplace("map" + index, owned_object::make_map());
    }

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);
    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_STREQ((*it).ptr()->parameterName, ("str" + index).c_str());
        EXPECT_STREQ((*it).as<const char *>(), ("val" + index).c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), i + 1);

        for (unsigned j = 0; j < i; j++) {
            EXPECT_STREQ(path[j].c_str(), ("map" + std::to_string(j)).c_str());
        }
        EXPECT_STREQ(path.back().c_str(), ("str" + index).c_str());
        ++it;
    }

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestMapNoScalars)
{
    auto object = owned_object::make_map();
    for (unsigned i = 0; i < 50; i++) { object.emplace("key", owned_object::make_map()); }

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);

    EXPECT_FALSE(it);
    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestContainerMix)
{
    auto object = yaml_to_object<owned_object>(R"(
        {
            root: {
                key0: [value0_0, value0_1, {
                    key0_0: value0_2
                }, value0_3],
                key1: value1_0,
                key2: {
                    key2_0: value2_0,
                    key2_1: value2_1,
                    key2_2: [value2_2, value2_3]
                }
            }
        }
    )");

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    {
        ddwaf::value_iterator it(object, {}, exclude);

        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"value0_0", {"root", "key0", "0"}}, {"value0_1", {"root", "key0", "1"}},
            {"value0_2", {"root", "key0", "2", "key0_0"}}, {"value0_3", {"root", "key0", "3"}},
            {"value1_0", {"root", "key1"}}, {"value2_0", {"root", "key2", "key2_0"}},
            {"value2_1", {"root", "key2", "key2_1"}}, {"value2_2", {"root", "key2", "key2_2", "0"}},
            {"value2_3", {"root", "key2", "key2_2", "1"}}};

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE(it);
    }
}

TEST(TestValueIterator, TestInvalidObjectPath)
{
    owned_object object;

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    {
        std::vector<std::string> key_path{"key"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0", "value"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }
}

TEST(TestValueIterator, TestSimplePath)
{
    auto object = owned_object::make_map({{"key", "value"}, {"key1", "value"}, {"key2", "value"}});

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    {
        std::vector<std::string> key_path{"key"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_TRUE(it);

        std::vector<std::string> expected_path = {"key"};
        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_EQ(path, expected_path);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0", "value"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }
}

TEST(TestValueIterator, TestMultiPath)
{
    auto object = owned_object::make_map(
        {{"first", owned_object::make_map({{"second", owned_object::make_map({{"third", "final"},
                                                          {"value", "value_third"}})},
                       {"value", "value_second"}})},
            {"value", "value_first"}});

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    {
        std::vector<std::string> key_path{"first"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_TRUE(it);

        EXPECT_STREQ((*it).as<const char *>(), "final");

        std::vector<std::string> expected_path = {"first", "second", "third"};
        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, expected_path);

        EXPECT_TRUE(++it);
        EXPECT_TRUE(it);

        EXPECT_STREQ((*it).as<const char *>(), "value_third");

        expected_path = decltype(expected_path){"first", "second", "value"};
        path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, expected_path);

        EXPECT_TRUE(++it);
        EXPECT_TRUE(it);

        EXPECT_STREQ((*it).as<const char *>(), "value_second");

        expected_path = decltype(expected_path){"first", "value"};
        path = it.get_current_path();
        EXPECT_EQ(path.size(), 2);
        EXPECT_EQ(path, expected_path);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"first", "second"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_TRUE(it);

        EXPECT_STREQ((*it).as<const char *>(), "final");

        std::vector<std::string> expected_path = {"first", "second", "third"};
        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, expected_path);

        EXPECT_TRUE(++it);
        EXPECT_TRUE(it);

        EXPECT_STREQ((*it).as<const char *>(), "value_third");

        expected_path = decltype(expected_path){"first", "second", "value"};
        path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, expected_path);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"first", "second", "third"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_TRUE(it);

        EXPECT_STREQ((*it).as<const char *>(), "final");

        std::vector<std::string> expected_path = {"first", "second", "third"};
        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, expected_path);

        EXPECT_FALSE(++it);
    }
}

TEST(TestValueIterator, TestContainerMixPath)
{
    auto object = yaml_to_object<owned_object>(R"(
        {
            root: {
                key0: [value0_0, value0_1, {
                    key0_0: value0_2
                }, value0_3],
                key1: value1_0,
                key2: {
                    key2_0: value2_0,
                    key2_1: value2_1,
                    key2_2: [value2_2, value2_3]
                }
            }
        }
    )");

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"value0_0", {"root", "key0", "0"}},
            {"value0_1", {"root", "key0", "1"}},
            {"value0_2", {"root", "key0", "2", "key0_0"}},
            {"value0_3", {"root", "key0", "3"}},
        };

        std::vector<std::string> key_path{"root", "key0"};
        ddwaf::value_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE(it);
    }

    {
        std::vector<std::string> key_path{"root", "key1"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_STREQ((*it).as<const char *>(), "value1_0");

        auto it_path = it.get_current_path();
        std::vector<std::string> path = {"root", "key1"};
        EXPECT_EQ(it_path, path);
        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"value2_0", {"root", "key2", "key2_0"}}, {"value2_1", {"root", "key2", "key2_1"}},
            {"value2_2", {"root", "key2", "key2_2", "0"}},
            {"value2_3", {"root", "key2", "key2_2", "1"}}};

        std::vector<std::string> key_path{"root", "key2"};
        ddwaf::value_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE(it);
    }
}

TEST(TestValueIterator, TestContainerMixInvalidPath)
{
    auto object = yaml_to_object<owned_object>(R"(
        {
            root: {
                key0: [value0_0, value0_1, {
                    key0_0: value0_2
                }, value0_3],
                key1: value1_0,
                key2: {
                    key2_0: value2_0,
                    key2_1: value2_1,
                    key2_2: [value2_2, value2_3]
                }
            }
        }
    )");

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{.persistent = persistent, .ephemeral = {}};
    {
        std::vector<std::string> key_path{"rat"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);
    }

    {
        std::vector<std::string> key_path{"root", "cat"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);
    }

    {
        std::vector<std::string> key_path{"root", "key2", "key2_2", "0", "1", "2", "3"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);
    }
}

TEST(TestValueIterator, TestExcludeSingleObject)
{
    auto object = owned_object::make_map({{"key", "value"}});

    std::unordered_set<object_view> persistent{object.at(0)};
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(object, {}, exclude);

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestExcludeMultipleObjects)
{
    auto root = owned_object::make_map({{"key", "value"}});

    auto map = root.emplace("other", owned_object::make_array({"hello", "bye"}));

    std::unordered_set<object_view> persistent{root.at(0), map.at(1)};
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::value_iterator it(root, {}, exclude);

    EXPECT_TRUE(it);
    EXPECT_STREQ((*it).as<const char *>(), "hello");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 2);
    EXPECT_STREQ(path[0].c_str(), "other");
    EXPECT_STREQ(path[1].c_str(), "0");

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestExcludeObjectInKeyPath)
{
    auto root = owned_object::make_map();
    auto child = root.emplace("parent", owned_object::make_map());
    child.emplace("child", "value");

    std::unordered_set<object_view> persistent{child.at(0)};
    exclusion::object_set_ref exclude{persistent, {}};
    std::vector<std::string> key_path{"parent", "child"};
    ddwaf::value_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestExcludeRootOfKeyPath)
{
    auto root = owned_object::make_map({{"parent", owned_object::make_map({{"child", "value"}})}});

    std::unordered_set<object_view> persistent{root.at(0)};

    exclusion::object_set_ref exclude{persistent, {}};
    std::vector<std::string> key_path{"parent", "child"};
    ddwaf::value_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}
} // namespace
