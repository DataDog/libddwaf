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

TEST(TestKVIterator, TestInvalidIterator)
{
    owned_object object;

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE((*it).has_value());

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    EXPECT_FALSE((*it).has_value());
}

TEST(TestKVIterator, TestStringScalar)
{
    owned_object object{"value"};

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_EQ(*it, object_view{object});

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    EXPECT_FALSE((*it).has_value());
}

TEST(TestKVIterator, TestUnsignedScalar)
{
    owned_object object{22U};

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_EQ(*it, object_view{object});

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestSignedScalar)
{
    owned_object object{22L};

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_EQ(*it, object_view{object});

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestArraySingleItem)
{
    auto object = object_builder::array({"string"});

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_STREQ((*it).as<const char *>(), "string");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "0");

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestArrayMultipleItems)
{
    auto object = object_builder::array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(std::to_string(i)); }

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::kv_iterator it(object, {}, exclude);

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

TEST(TestKVIterator, TestArrayMultipleNullAndInvalid)
{
    auto object = object_builder::array();
    for (unsigned i = 0; i < 25; i++) {
        object.emplace_back(std::to_string(i));
        object.emplace_back(owned_object{});
        object.emplace_back(owned_object::make_null());
    }

    EXPECT_EQ(object.size(), 75);

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::kv_iterator it(object, {}, exclude);

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

TEST(TestKVIterator, TestDeepArray)
{
    auto object = object_builder::array();
    borrowed_object array{object};
    for (unsigned i = 0; i < 10; i++) {
        array.emplace_back("val" + std::to_string(i));
        array = array.emplace_back(object_builder::array());
    }

    std::unordered_set<object_view> persistent;
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::kv_iterator it(object, {}, exclude);
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

TEST(TestKVIterator, TestArrayNoScalars)
{
    auto object = object_builder::array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(object_builder::array()); }

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);

    EXPECT_FALSE((*it).has_value());
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestMapSingleItem)
{
    auto object = object_builder::map({{"key", "value"}});

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);
    {
        EXPECT_TRUE((bool)it);
        EXPECT_STREQ((*it).as<const char *>(), "key");

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), "key");
    }

    {
        EXPECT_TRUE(++it);
        EXPECT_STREQ((*it).as<const char *>(), "value");

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), "key");
    }

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestMapMultipleItems)
{
    auto object = object_builder::map();

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        object.emplace("key" + index, "value" + index);
    }

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;

        EXPECT_TRUE((bool)it);
        EXPECT_STREQ((*it).as<const char *>(), key.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), key.c_str());

        EXPECT_TRUE(++it);
        EXPECT_STREQ((*it).as<const char *>(), value.c_str());

        path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), key.c_str());

        ++it;
    }

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestMapMultipleNullAndInvalid)
{
    auto object = object_builder::map();

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

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 25; i++) {
        {
            auto index = std::to_string(i * 3);
            std::string key = "key" + index;
            std::string value = "value" + index;

            EXPECT_TRUE((bool)it);
            EXPECT_STREQ((*it).as<const char *>(), key.c_str());

            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), 1);
            EXPECT_STREQ(path[0].c_str(), key.c_str());

            EXPECT_TRUE(++it);
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            path = it.get_current_path();
            EXPECT_EQ(path.size(), 1);
            EXPECT_STREQ(path[0].c_str(), key.c_str());
        }

        ++it;

        {
            auto index = std::to_string(i * 3 + 1);
            std::string key = "key" + index;

            EXPECT_TRUE((bool)it);

            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), 1);
            EXPECT_STREQ(path[0].c_str(), key.c_str());
        }

        ++it;

        {
            auto index = std::to_string(i * 3 + 2);
            std::string key = "key" + index;

            EXPECT_TRUE((bool)it);

            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), 1);
            EXPECT_STREQ(path[0].c_str(), key.c_str());
        }
        ++it;
    }

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestDeepMap)
{
    auto object = object_builder::map();
    borrowed_object map{object};

    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);
        map.emplace("str" + index, "val" + index);
        map = map.emplace("map" + index, object_builder::map());
    }

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_STREQ((*it).as<const char *>(), ("str" + index).c_str());

        {
            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), i + 1);
            for (unsigned j = 0; j < i; j++) {
                auto key = "map" + std::to_string(j);
                EXPECT_STREQ(path[j].c_str(), key.c_str());
            }
            EXPECT_STREQ(path.back().c_str(), ("str" + index).c_str());
        }

        EXPECT_TRUE(++it);
        EXPECT_STREQ((*it).as<const char *>(), ("val" + index).c_str());
        {
            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), i + 1);
            for (unsigned j = 0; j < i; j++) {
                EXPECT_STREQ(path[j].c_str(), ("map" + std::to_string(j)).c_str());
            }
            EXPECT_STREQ(path.back().c_str(), ("str" + index).c_str());
        }

        EXPECT_TRUE(++it);
        EXPECT_STREQ((*it).as<const char *>(), ("map" + index).c_str());
        {
            auto path = it.get_current_path();
            EXPECT_EQ(path.size(), i + 1);
            for (unsigned j = 0; j < i + 1; j++) {
                auto key = "map" + std::to_string(j);
                EXPECT_STREQ(path[j].c_str(), key.c_str());
            }
        }

        ++it;
    }

    EXPECT_FALSE(++it);
}

// Ensure the key on the root object is not reported.
// This key will usually correspond to one of the provided
// addesses (e.g. server.request.query).
TEST(TestKVIterator, TestNoRootKey)
{
    auto object = object_builder::map();
    object.emplace("root", object_builder::map({{"key", "value"}}));

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object.at(0), {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_STREQ((*it).as<const char *>(), "key");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "key");

    EXPECT_TRUE(++it);
    EXPECT_STREQ((*it).as<const char *>(), "value");

    path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "key");

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestContainerMix)
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
        exclusion::object_set_ref exclude;
        ddwaf::kv_iterator it(object, {}, exclude);

        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"root", {"root"}},
            {"key0", {"root", "key0"}},
            {"value0_0", {"root", "key0", "0"}},
            {"value0_1", {"root", "key0", "1"}},
            {"key0_0", {"root", "key0", "2", "key0_0"}},
            {"value0_2", {"root", "key0", "2", "key0_0"}},
            {"value0_3", {"root", "key0", "3"}},
            {"key1", {"root", "key1"}},
            {"value1_0", {"root", "key1"}},
            {"key2", {"root", "key2"}},
            {"key2_0", {"root", "key2", "key2_0"}},
            {"value2_0", {"root", "key2", "key2_0"}},
            {"key2_1", {"root", "key2", "key2_1"}},
            {"value2_1", {"root", "key2", "key2_1"}},
            {"key2_2", {"root", "key2", "key2_2"}},
            {"value2_2", {"root", "key2", "key2_2", "0"}},
            {"value2_3", {"root", "key2", "key2_2", "1"}},
        };

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }
}

TEST(TestKVIterator, TestMapNoScalars)
{
    auto object = object_builder::map();
    for (unsigned i = 0; i < 50; i++) { object.emplace("key", object_builder::map()); }

    exclusion::object_set_ref exclude;
    ddwaf::kv_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 50; i++) {
        EXPECT_TRUE((bool)it);
        EXPECT_STREQ((*it).as<const char *>(), "key");

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), "key");
        ++it;
    }

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestInvalidObjectPath)
{
    owned_object object;

    exclusion::object_set_ref exclude;
    std::vector<std::string> key_path{"key", "0", "value"};
    ddwaf::kv_iterator it(object, key_path, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestSimplePath)
{
    owned_object object;

    {
        std::vector<std::string> key_path{"key"};
        ddwaf::kv_iterator it(object, key_path, {});
        EXPECT_FALSE((bool)it);
        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0"};
        ddwaf::kv_iterator it(object, key_path, {});
        EXPECT_FALSE((bool)it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0", "value"};
        ddwaf::kv_iterator it(object, key_path, {});
        EXPECT_FALSE((bool)it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }
}

TEST(TestKVIterator, TestMultiPath)
{
    auto object = object_builder::map(
        {{"first", object_builder::map({{"second", object_builder::map({{"third", "final"},
                                                       {"value", "value_third"}})},
                       {"value", "value_second"}})},
            {"value", "value_first"}});

    exclusion::object_set_ref exclude;
    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"second", {"first", "second"}},
            {"third", {"first", "second", "third"}},
            {"final", {"first", "second", "third"}},
            {"value", {"first", "second", "value"}},
            {"value_third", {"first", "second", "value"}},
            {"value", {"first", "value"}},
            {"value_second", {"first", "value"}},
        };

        std::vector<std::string> key_path{"first"};
        ddwaf::kv_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"third", {"first", "second", "third"}},
            {"final", {"first", "second", "third"}},
            {"value", {"first", "second", "value"}},
            {"value_third", {"first", "second", "value"}},
        };

        std::vector<std::string> key_path{"first", "second"};
        ddwaf::kv_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"final", {"first", "second", "third"}},
        };

        std::vector<std::string> key_path{"first", "second", "third"};
        ddwaf::kv_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }
}

TEST(TestKVIterator, TestContainerMixPath)
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

    exclusion::object_set_ref exclude;
    {
        std::vector<std::string> key_path{"root", "key0"};
        ddwaf::kv_iterator it(object, key_path, exclude);

        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"value0_0", {"root", "key0", "0"}},
            {"value0_1", {"root", "key0", "1"}},
            {"key0_0", {"root", "key0", "2", "key0_0"}},
            {"value0_2", {"root", "key0", "2", "key0_0"}},
            {"value0_3", {"root", "key0", "3"}},
        };

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"root", "key1"};
        ddwaf::kv_iterator it(object, key_path, exclude);
        EXPECT_TRUE((bool)it);

        EXPECT_STREQ((*it).as<const char *>(), "value1_0");

        auto path = it.get_current_path();
        EXPECT_EQ(path, key_path);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"key2_0", {"root", "key2", "key2_0"}},
            {"value2_0", {"root", "key2", "key2_0"}},
            {"key2_1", {"root", "key2", "key2_1"}},
            {"value2_1", {"root", "key2", "key2_1"}},
            {"key2_2", {"root", "key2", "key2_2"}},
            {"value2_2", {"root", "key2", "key2_2", "0"}},
            {"value2_3", {"root", "key2", "key2_2", "1"}},
        };

        std::vector<std::string> key_path{"root", "key2"};
        ddwaf::kv_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }
}

TEST(TestKVIterator, TestContainerMixInvalidPath)
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

    exclusion::object_set_ref exclude;
    {
        std::vector<std::string> key_path{"rat"};
        ddwaf::kv_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"root", "cat"};
        ddwaf::kv_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"root", "key2", "key2_2", "0", "1", "2", "3"};
        ddwaf::kv_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }
}

TEST(TestKVIterator, TestExcludeSingleObject)
{
    auto object = object_builder::map({{"key", "value"}});

    std::unordered_set<object_view> persistent{object.at(0)};

    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::kv_iterator it(object, {}, exclude);

    EXPECT_FALSE(it);
}

TEST(TestKVIterator, TestExcludeMultipleObjects)
{
    auto root = object_builder::map({{"key", "value"}});

    auto map =
        root.emplace("other", object_builder::map({{"hello_key", "hello"}, {"bye_key", "bye"}}));

    std::unordered_set<object_view> persistent{root.at(0), map.at(1)};
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::kv_iterator it(root, {}, exclude);

    EXPECT_TRUE(it);
    EXPECT_STREQ((*it).as<const char *>(), "other");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "other");

    EXPECT_STREQ((*it).as<const char *>(), "other");

    EXPECT_TRUE(++it);
    EXPECT_STREQ((*it).as<const char *>(), "hello_key");

    path = it.get_current_path();
    EXPECT_EQ(path.size(), 2);
    EXPECT_STREQ(path[0].c_str(), "other");
    EXPECT_STREQ(path[1].c_str(), "hello_key");

    EXPECT_TRUE(++it);
    EXPECT_STREQ((*it).as<const char *>(), "hello");
    path = it.get_current_path();
    EXPECT_EQ(path.size(), 2);
    EXPECT_STREQ(path[0].c_str(), "other");
    EXPECT_STREQ(path[1].c_str(), "hello_key");

    EXPECT_FALSE(++it);
}

TEST(TestKVIterator, TestExcludeObjectInKeyPath)
{
    auto root = object_builder::map();
    auto child = root.emplace("parent", object_builder::map());
    child.emplace("child", "value");

    std::unordered_set<object_view> persistent{child.at(0)};
    exclusion::object_set_ref exclude{persistent, {}};
    std::vector<std::string> key_path{"parent", "child"};
    ddwaf::kv_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}

TEST(TestKVIterator, TestExcludeRootOfKeyPath)
{
    auto root = object_builder::map({{"parent", object_builder::map({{"child", "value"}})}});

    std::unordered_set<object_view> persistent{root.at(0)};
    exclusion::object_set_ref exclude{persistent, {}};
    std::vector<std::string> key_path{"parent", "child"};
    ddwaf::kv_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}

} // namespace
