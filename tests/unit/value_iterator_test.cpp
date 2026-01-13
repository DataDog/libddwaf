// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"
#include "context_allocator.hpp"
#include "iterator.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestValueIterator, TestInvalidIterator)
{
    owned_object object = owned_object{};

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_FALSE(it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    EXPECT_FALSE((*it).has_value());
}

TEST(TestValueIterator, TestStringScalar)
{
    owned_object object = test::ddwaf_object_da::make_string("value");

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_EQ(*it, object_view{object});

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    EXPECT_FALSE((*it).has_value());
}

TEST(TestValueIterator, TestUnsignedScalar)
{
    owned_object object = test::ddwaf_object_da::make_unsigned(22U);

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_EQ(*it, object_view{object});

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestSignedScalar)
{
    owned_object object = test::ddwaf_object_da::make_signed(22L);

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_EQ(*it, object_view{object});

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestArraySingleItem)
{
    auto object = object_builder_da::array({"string"});

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_STR((*it).as<std::string_view>(), "string");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_EQ(std::get<int64_t>(path[0]), 0);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestArrayMultipleItems)
{
    auto object = object_builder_da::array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(std::to_string(i)); }

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);

    unsigned index = 0;
    do {
        auto index_str = std::to_string(index);
        EXPECT_TRUE(it);
        EXPECT_STR((*it).as<std::string_view>(), index_str);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_EQ(std::get<int64_t>(path[0]), index);
        ++index;
    } while (++it);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestArrayMultipleNullAndInvalid)
{
    auto object = object_builder_da::array();
    for (unsigned i = 0; i < 25; i++) {
        object.emplace_back(std::to_string(i));
        object.emplace_back(owned_object{});
        object.emplace_back(owned_object::make_null());
    }

    EXPECT_EQ(object.size(), 75);

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);

    // Null and invalid objects should be skipped
    unsigned index = 0;
    do {
        EXPECT_TRUE(it);
        EXPECT_STR((*it).as<std::string_view>(), std::to_string(index));

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_EQ(std::get<int64_t>(path[0]), index * 3);
        ++index;
    } while (++it);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestDeepArray)
{
    auto object = object_builder_da::array();
    borrowed_object array{object};
    for (unsigned i = 0; i < 10; i++) {
        array.emplace_back("val" + std::to_string(i));
        array = array.emplace_back(object_builder_da::array());
    }

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);
    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_STR((*it).as<std::string_view>(), ("val" + index));

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), i + 1);

        for (unsigned j = 0; j < i; j++) { EXPECT_EQ(std::get<int64_t>(path[j]), 1); }
        ++it;
    }

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestArrayNoScalars)
{
    auto object = object_builder_da::array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(object_builder_da::array()); }

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);

    EXPECT_FALSE(it);
    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestMapSingleItem)
{
    auto object = object_builder_da::map({{"key", "value"}});

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);

    EXPECT_TRUE(it);
    EXPECT_STR((*it).as<std::string_view>(), "value");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STR(std::get<std::string_view>(path[0]), "key");

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestMapMultipleItems)
{
    auto object = object_builder_da::map();

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        object.emplace("key" + index, "value" + index);
    }

    std::unordered_set<object_cache_key> context{};
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;

        EXPECT_TRUE(it);
        EXPECT_STR((*it).as<std::string_view>(), value);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STR(std::get<std::string_view>(path[0]), key);
        ++it;
    }

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestMapMultipleMultipleNullAndInvalid)
{
    auto object = object_builder_da::map();

    for (unsigned i = 0; i < 25; i++) {
        {
            auto index = std::to_string(i * 3);
            object.emplace("key" + index, "value" + index);
        }

        {
            auto index = std::to_string(i * 3 + 1);
            object.emplace("key" + index, owned_object::make_null());
        }

        {
            auto index = std::to_string(i * 3 + 2);
            object.emplace("key" + index, owned_object{});
        }
    }

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 25; i++) {
        auto index = std::to_string(i * 3);
        std::string key = "key" + index;
        std::string value = "value" + index;

        EXPECT_TRUE(it);
        EXPECT_STR((*it).as<std::string_view>(), value);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STR(std::get<std::string_view>(path[0]), key);
        ++it;
    }

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestDeepMap)
{
    auto object = object_builder_da::map();
    borrowed_object map{object};

    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);
        map.emplace("str" + index, "val" + index);
        map = map.emplace("map" + index, object_builder_da::map());
    }

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);
    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_STR((*it).as<std::string_view>(), ("val" + index));

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), i + 1);

        for (unsigned j = 0; j < i; j++) {
            EXPECT_STR(std::get<std::string_view>(path[j]), ("map" + std::to_string(j)));
        }
        EXPECT_STR(std::get<std::string_view>(path.back()), ("str" + index));
        ++it;
    }

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestMapNoScalars)
{
    auto object = object_builder_da::map();
    for (unsigned i = 0; i < 50; i++) { object.emplace("key", object_builder_da::map()); }

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
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

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    {
        ddwaf::value_iterator it(object, {}, exclude);

        std::vector<std::pair<std::string, std::vector<std::variant<std::string_view, int64_t>>>>
            values = {{"value0_0", {"root", "key0", 0}}, {"value0_1", {"root", "key0", 1}},
                {"value0_2", {"root", "key0", 2, "key0_0"}}, {"value0_3", {"root", "key0", 3}},
                {"value1_0", {"root", "key1"}}, {"value2_0", {"root", "key2", "key2_0"}},
                {"value2_1", {"root", "key2", "key2_1"}},
                {"value2_2", {"root", "key2", "key2_2", 0}},
                {"value2_3", {"root", "key2", "key2_2", 1}}};

        for (auto &[value, path] : values) {
            EXPECT_STR((*it).as<std::string_view>(), value);

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE(it);
    }
}

TEST(TestValueIterator, TestInvalidObjectPath)
{
    owned_object object = owned_object{};

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    {
        std::vector<std::variant<std::string, int64_t>> key_path{"key"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"key", "0"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"key", "0", "value"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }
}

TEST(TestValueIterator, TestSimplePath)
{
    auto object = object_builder_da::map({{"key", "value"}, {"key1", "value"}, {"key2", "value"}});

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    {
        std::vector<std::variant<std::string, int64_t>> key_path{"key"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_TRUE(it);

        std::vector<std::variant<std::string, int64_t>> expected_path = {"key"};
        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_EQ(path, convert_key_path(expected_path));

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"key", "0"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"key", "0", "value"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }
}

TEST(TestValueIterator, TestMultiPath)
{
    auto object = object_builder_da::map(
        {{"first", object_builder_da::map({{"second", object_builder_da::map({{"third", "final"},
                                                          {"value", "value_third"}})},
                       {"value", "value_second"}})},
            {"value", "value_first"}});

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    {
        std::vector<std::variant<std::string, int64_t>> key_path{"first"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_TRUE(it);

        EXPECT_STR((*it).as<std::string_view>(), "final");

        std::vector<std::variant<std::string, int64_t>> expected_path = {
            "first", "second", "third"};
        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, convert_key_path(expected_path));

        EXPECT_TRUE(++it);
        EXPECT_TRUE(it);

        EXPECT_STR((*it).as<std::string_view>(), "value_third");

        expected_path = decltype(expected_path){"first", "second", "value"};
        path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, convert_key_path(expected_path));

        EXPECT_TRUE(++it);
        EXPECT_TRUE(it);

        EXPECT_STR((*it).as<std::string_view>(), "value_second");

        expected_path = decltype(expected_path){"first", "value"};
        path = it.get_current_path();
        EXPECT_EQ(path.size(), 2);
        EXPECT_EQ(path, convert_key_path(expected_path));

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"first", "second"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_TRUE(it);

        EXPECT_STR((*it).as<std::string_view>(), "final");

        std::vector<std::variant<std::string, int64_t>> expected_path = {
            "first", "second", "third"};
        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, convert_key_path(expected_path));

        EXPECT_TRUE(++it);
        EXPECT_TRUE(it);

        EXPECT_STR((*it).as<std::string_view>(), "value_third");

        expected_path = decltype(expected_path){"first", "second", "value"};
        path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, convert_key_path(expected_path));

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"first", "second", "third"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_TRUE(it);

        EXPECT_STR((*it).as<std::string_view>(), "final");

        std::vector<std::variant<std::string, int64_t>> expected_path = {
            "first", "second", "third"};
        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 3);
        EXPECT_EQ(path, convert_key_path(expected_path));

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

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    {
        std::vector<std::pair<std::string, std::vector<std::variant<std::string_view, int64_t>>>>
            values = {
                {"value0_0", {"root", "key0", 0}},
                {"value0_1", {"root", "key0", 1}},
                {"value0_2", {"root", "key0", 2, "key0_0"}},
                {"value0_3", {"root", "key0", 3}},
            };

        std::vector<std::variant<std::string, int64_t>> key_path{"root", "key0"};
        ddwaf::value_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STR((*it).as<std::string_view>(), value);

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE(it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"root", "key1"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_STR((*it).as<std::string_view>(), "value1_0");

        auto it_path = it.get_current_path();
        std::vector<std::variant<std::string_view, int64_t>> path = {"root", "key1"};
        EXPECT_EQ(it_path, path);
        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::pair<std::string, std::vector<std::variant<std::string_view, int64_t>>>>
            values = {{"value2_0", {"root", "key2", "key2_0"}},
                {"value2_1", {"root", "key2", "key2_1"}},
                {"value2_2", {"root", "key2", "key2_2", 0}},
                {"value2_3", {"root", "key2", "key2_2", 1}}};

        std::vector<std::variant<std::string, int64_t>> key_path{"root", "key2"};
        ddwaf::value_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STR((*it).as<std::string_view>(), value);

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

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};
    {
        std::vector<std::variant<std::string, int64_t>> key_path{"rat"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"root", "cat"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{
            "root", "key2", "key2_2", "0", "1", "2", "3"};
        ddwaf::value_iterator it(object, key_path, exclude);
        EXPECT_FALSE(it);
    }
}

TEST(TestValueIterator, TestExcludeSingleObject)
{
    auto object = object_builder_da::map({{"key", "value"}});

    std::unordered_set<object_cache_key> context{object.at(0)};
    object_set_ref exclude{context};
    ddwaf::value_iterator it(object, {}, exclude);

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestExcludeMultipleObjects)
{
    auto root = object_builder_da::map({{"key", "value"}});

    auto map = root.emplace("other", object_builder_da::array({"hello", "bye"}));

    std::unordered_set<object_cache_key> context{root.at(0), map.at(1)};
    object_set_ref exclude{context};
    ddwaf::value_iterator it(root, {}, exclude);

    EXPECT_TRUE(it);
    EXPECT_STR((*it).as<std::string_view>(), "hello");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 2);
    EXPECT_STR(std::get<std::string_view>(path[0]), "other");
    EXPECT_EQ(std::get<int64_t>(path[1]), 0);

    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestExcludeObjectInKeyPath)
{
    auto root = object_builder_da::map();
    auto child = root.emplace("parent", object_builder_da::map());
    child.emplace("child", "value");

    std::unordered_set<object_cache_key> context{child.at(0)};
    object_set_ref exclude{context};
    std::vector<std::variant<std::string, int64_t>> key_path{"parent", "child"};
    ddwaf::value_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestExcludeRootOfKeyPath)
{
    auto root = object_builder_da::map({{"parent", object_builder_da::map({{"child", "value"}})}});

    std::unordered_set<object_cache_key> context{root.at(0)};

    object_set_ref exclude{context};
    std::vector<std::variant<std::string, int64_t>> key_path{"parent", "child"};
    ddwaf::value_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}

TEST(TestValueIterator, TestNegativeIndexInPath)
{
    auto object = object_builder_da::map(
        {{"root", object_builder_da::map({{"arr", object_builder_da::array({"a", "b", "c"})}})}});

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};

    std::vector<std::variant<std::string, int64_t>> key_path{"root", "arr", -1};
    ddwaf::value_iterator it(object, key_path, exclude);

    EXPECT_TRUE(it);
    EXPECT_STR((*it).as<std::string_view>(), "c");

    auto it_path = it.get_current_path();
    std::vector<std::variant<std::string_view, int64_t>> expected_path = {"root", "arr", -1};
    EXPECT_EQ(it_path, expected_path);
    EXPECT_FALSE(++it);
}

TEST(TestValueIterator, TestPositiveIndexInPath)
{
    auto object = object_builder_da::map(
        {{"root", object_builder_da::map({{"arr", object_builder_da::array({"a", "b", "c"})}})}});

    std::unordered_set<object_cache_key> context;
    object_set_ref exclude{context};

    std::vector<std::variant<std::string, int64_t>> key_path{"root", "arr", 1};
    ddwaf::value_iterator it(object, key_path, exclude);

    EXPECT_TRUE(it);
    EXPECT_STR((*it).as<std::string_view>(), "b");

    auto it_path = it.get_current_path();
    std::vector<std::variant<std::string_view, int64_t>> expected_path = {"root", "arr", 1};
    EXPECT_EQ(it_path, expected_path);
    EXPECT_FALSE(++it);
}
} // namespace
