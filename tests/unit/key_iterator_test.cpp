// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "iterator.hpp"

using namespace ddwaf;

namespace {

TEST(TestKeyIterator, TestInvalidIterator)
{
    owned_object object;

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    EXPECT_FALSE((*it).has_value());
}

TEST(TestKeyIterator, TestStringScalar)
{
    owned_object object{"value"};

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    EXPECT_FALSE((*it).has_value());
}

TEST(TestKeyIterator, TestUnsignedScalar)
{
    owned_object object{22U};

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestSignedScalar)
{
    owned_object object{22L};

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestArraySingleItem)
{
    auto object = object_builder::array({"string"});

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);
}

TEST(TestKeyIterator, TestArrayMultipleItems)
{
    auto object = object_builder::array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(std::to_string(i)); }

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);
}

TEST(TestKeyIterator, TestDeepArray)
{
    auto object = object_builder::array();
    borrowed_object array{object};
    for (unsigned i = 0; i < 10; i++) {
        array.emplace_back("val" + std::to_string(i));
        array = array.emplace_back(object_builder::array());
    }

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);
}

TEST(TestKeyIterator, TestArrayNoScalars)
{
    auto object = object_builder::array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(object_builder::array()); }

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestMapSingleItem)
{
    auto object = object_builder::map({{"key", "value"}});

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_STR((*it).as<std::string_view>(), "key");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STR(std::get<std::string_view>(path[0]), "key");

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestMapMultipleItems)
{
    auto object = object_builder::map();

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        object.emplace("key" + index, "value" + index);
    }

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;

        EXPECT_TRUE((bool)it);
        EXPECT_STR((*it).as<std::string_view>(), key);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STR(std::get<std::string_view>(path[0]), key);
        ++it;
    }

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestMapMultipleNullAndInvalid)
{
    auto object = object_builder::map();

    for (unsigned i = 0; i < 25; i++) {
        {
            auto index = std::to_string(i * 3);
            object.emplace("key" + index, "value" + index);
        }

        {
            auto index = std::to_string((i * 3) + 1);
            object.emplace("key" + index, owned_object::make_null());
        }

        {
            auto index = std::to_string((i * 3) + 2);
            object.emplace("key" + index, owned_object{});
        }
    }

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 25; i++) {
        {
            auto index = std::to_string(i * 3);
            std::string key = "key" + index;

            EXPECT_TRUE((bool)it);
            EXPECT_STR((*it).as<std::string_view>(), key);

            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), 1);
            EXPECT_STR(std::get<std::string_view>(path[0]), key);
        }

        ++it;

        {
            auto index = std::to_string((i * 3) + 1);
            std::string key = "key" + index;

            EXPECT_TRUE((bool)it);

            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), 1);
            EXPECT_STR(std::get<std::string_view>(path[0]), key);
        }

        ++it;

        {
            auto index = std::to_string((i * 3) + 2);
            std::string key = "key" + index;

            EXPECT_TRUE((bool)it);

            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), 1);
            EXPECT_STR(std::get<std::string_view>(path[0]), key);
        }
        ++it;
    }

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestDeepMap)
{
    auto object = object_builder::map();
    borrowed_object map{object};

    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);
        map.emplace("str" + index, "val" + index);
        map = map.emplace("map" + index, object_builder::map());
    }

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_STR((*it).as<std::string_view>(), ("str" + index));

        {
            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), i + 1);
            for (unsigned j = 0; j < i; j++) {
                auto key = "map" + std::to_string(j);
                EXPECT_STR(std::get<std::string_view>(path[j]), key);
            }
            EXPECT_STR(std::get<std::string_view>(path.back()), ("str" + index));
        }

        EXPECT_TRUE(++it);
        EXPECT_STR((*it).as<std::string_view>(), ("map" + index));

        {
            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), i + 1);
            for (unsigned j = 0; j < i + 1; j++) {
                auto key = "map" + std::to_string(j);
                EXPECT_STR(std::get<std::string_view>(path[j]), key);
            }
        }

        ++it;
    }

    EXPECT_FALSE(++it);
}

// Ensure the key on the root object is not reported.
// This key will usually correspond to one of the provided
// addesses (e.g. server.request.query).
TEST(TestKeyIterator, TestNoRootKey)
{
    auto object = object_builder::map();
    object.emplace("root", object_builder::map({{"key", "value"}}));

    object_set_ref exclude;
    ddwaf::key_iterator it(object.at(0), {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_STR((*it).as<std::string_view>(), "key");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STR(std::get<std::string_view>(path[0]), "key");

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestContainerMix)
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

    {
        object_set_ref exclude;
        ddwaf::key_iterator it(object, {}, exclude);

        std::vector<std::pair<std::string, std::vector<std::variant<std::string_view, int64_t>>>>
            values = {
                {"root", {"root"}},
                {"key0", {"root", "key0"}},
                {"key0_0", {"root", "key0", 2, "key0_0"}},
                {"key1", {"root", "key1"}},
                {"key2", {"root", "key2"}},
                {"key2_0", {"root", "key2", "key2_0"}},
                {"key2_1", {"root", "key2", "key2_1"}},
                {"key2_2", {"root", "key2", "key2_2"}},
            };

        for (auto &[value, path] : values) {
            EXPECT_STR((*it).as<std::string_view>(), value);

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }
}

TEST(TestKeyIterator, TestMapNoScalars)
{
    auto object = object_builder::map();
    for (unsigned i = 0; i < 50; i++) { object.emplace("key", object_builder::map()); }

    object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 50; i++) {
        EXPECT_TRUE((bool)it);
        EXPECT_STR((*it).as<std::string_view>(), "key");

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STR(std::get<std::string_view>(path[0]), "key");
        ++it;
    }

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestInvalidObjectPath)
{
    owned_object object;

    object_set_ref exclude;
    std::vector<std::variant<std::string, int64_t>> key_path{"key", "0", "value"};
    ddwaf::key_iterator it(object, key_path, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestSimplePath)
{
    auto object = object_builder::map({{"key", "value"}, {"key1", "value"}, {"key2", "value"}});

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"key"};
        ddwaf::key_iterator it(object, key_path, {});
        EXPECT_FALSE((bool)it);
        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"key", "0"};
        ddwaf::key_iterator it(object, key_path, {});
        EXPECT_FALSE((bool)it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"key", "0", "value"};
        ddwaf::key_iterator it(object, key_path, {});
        EXPECT_FALSE((bool)it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }
}

TEST(TestKeyIterator, TestMultiPath)
{
    auto object = object_builder::map(
        {{"first", object_builder::map({{"second", object_builder::map({{"third", "final"},
                                                       {"value", "value_third"}})},
                       {"value", "value_second"}})},
            {"value", "value_first"}});

    object_set_ref exclude;
    {
        std::vector<std::pair<std::string, std::vector<std::variant<std::string_view, int64_t>>>>
            values = {
                {"second", {"first", "second"}},
                {"third", {"first", "second", "third"}},
                {"value", {"first", "second", "value"}},
                {"value", {"first", "value"}},
            };

        std::vector<std::variant<std::string, int64_t>> key_path{"first"};
        ddwaf::key_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STR((*it).as<std::string_view>(), value);

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::pair<std::string, std::vector<std::variant<std::string_view, int64_t>>>>
            values = {
                {"third", {"first", "second", "third"}},
                {"value", {"first", "second", "value"}},
            };

        std::vector<std::variant<std::string, int64_t>> key_path{"first", "second"};
        ddwaf::key_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STR((*it).as<std::string_view>(), value);

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"first", "second", "third"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }
}

TEST(TestKeyIterator, TestContainerMixPath)
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

    object_set_ref exclude;
    {
        std::vector<std::variant<std::string, int64_t>> key_path{"root", "key0"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_TRUE((bool)it);
        EXPECT_STR((*it).as<std::string_view>(), "key0_0");

        auto it_path = it.get_current_path();
        std::vector<std::variant<std::string_view, int64_t>> path = {"root", "key0", 2, "key0_0"};
        EXPECT_EQ(it_path, path);

        EXPECT_FALSE(++it);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"root", "key1"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::pair<std::string, std::vector<std::variant<std::string_view, int64_t>>>>
            values = {
                {"key2_0", {"root", "key2", "key2_0"}},
                {"key2_1", {"root", "key2", "key2_1"}},
                {"key2_2", {"root", "key2", "key2_2"}},
            };

        std::vector<std::variant<std::string, int64_t>> key_path{"root", "key2"};
        ddwaf::key_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STR((*it).as<std::string_view>(), value);

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }
}

TEST(TestKeyIterator, TestContainerMixInvalidPath)
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

    object_set_ref exclude;
    {
        std::vector<std::variant<std::string, int64_t>> key_path{"rat"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"root", "cat"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{
            "root", "key2", "key2_2", 0, 1, 2, 3};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }
}

TEST(TestKeyIterator, TestExcludeSingleObject)
{
    auto object = object_builder::map({{"key", "value"}});

    std::unordered_set<object_cache_key> persistent{object.at(0)};

    object_set_ref exclude{persistent};
    ddwaf::key_iterator it(object, {}, exclude);

    EXPECT_FALSE(it);
}

TEST(TestKeyIterator, TestExcludeMultipleObjects)
{
    auto root = object_builder::map({{"key", "value"}});

    auto map =
        root.emplace("other", object_builder::map({{"hello_key", "hello"}, {"bye_key", "bye"}}));

    std::unordered_set<object_cache_key> persistent{root.at(0), map.at(1)};
    object_set_ref exclude{persistent};
    ddwaf::key_iterator it(root, {}, exclude);

    EXPECT_TRUE(it);
    EXPECT_STR((*it).as<std::string_view>(), "other");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STR(std::get<std::string_view>(path[0]), "other");

    EXPECT_STR((*it).as<std::string_view>(), "other");

    EXPECT_TRUE(++it);
    EXPECT_STR((*it).as<std::string_view>(), "hello_key");

    path = it.get_current_path();
    EXPECT_EQ(path.size(), 2);
    EXPECT_STR(std::get<std::string_view>(path[0]), "other");
    EXPECT_STR(std::get<std::string_view>(path[1]), "hello_key");

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestExcludeObjectInKeyPath)
{
    auto root = object_builder::map();
    auto child = root.emplace("parent", object_builder::map());
    child.emplace("child", "value");

    std::unordered_set<object_cache_key> persistent{child.at(0)};

    object_set_ref exclude{persistent};
    std::vector<std::variant<std::string, int64_t>> key_path{"parent", "child"};

    ddwaf::key_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}

TEST(TestKeyIterator, TestExcludeRootOfKeyPath)
{
    auto root = object_builder::map({{"parent", object_builder::map({{"child", "value"}})}});

    std::unordered_set<object_cache_key> persistent{root.at(0)};
    object_set_ref exclude{persistent};
    std::vector<std::variant<std::string, int64_t>> key_path{"parent", "child"};

    ddwaf::key_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}

} // namespace
