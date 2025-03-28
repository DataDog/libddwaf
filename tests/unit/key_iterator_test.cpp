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

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestStringScalar)
{
    owned_object object{"value"};

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestUnsignedScalar)
{
    owned_object object{22U};

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestSignedScalar)
{
    owned_object object{22L};

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestArraySingleItem)
{
    auto object = owned_object::make_array({"string"});

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);
}

TEST(TestKeyIterator, TestArrayMultipleItems)
{
    auto object = owned_object::make_array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(std::to_string(i)); }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);
}

TEST(TestKeyIterator, TestDeepArray)
{
    auto object = owned_object::make_array();
    borrowed_object array{object};
    for (unsigned i = 0; i < 10; i++) {
        array.emplace_back("val" + std::to_string(i));
        array = array.emplace_back(owned_object::make_array());
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);
}

TEST(TestKeyIterator, TestArrayNoScalars)
{
    auto object = owned_object::make_array();
    for (unsigned i = 0; i < 50; i++) { object.emplace_back(owned_object::make_array()); }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestMapSingleItem)
{
    auto object = owned_object::make_map({{"key", "value"}});

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_EQ((*it).ptr()->parameterName, nullptr);
    EXPECT_STREQ((*it).as<const char *>(), "key");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "key");

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestMapMultipleItems)
{
    auto object = owned_object::make_map();

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        object.emplace("key" + index, "value" + index);
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;

        EXPECT_TRUE((bool)it);
        EXPECT_STREQ((*it).as<const char *>(), key.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), key.c_str());
        ++it;
    }

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestMapMultipleNullAndInvalid)
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

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 25; i++) {
        {
            auto index = std::to_string(i * 3);
            std::string key = "key" + index;

            EXPECT_TRUE((bool)it);
            EXPECT_STREQ((*it).as<const char *>(), key.c_str());

            auto path = it.get_current_path();
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

TEST(TestKeyIterator, TestDeepMap)
{
    auto object = owned_object::make_map();
    borrowed_object map{object};

    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);
        map.emplace("str" + index, "val" + index);
        map = map.emplace("map" + index, owned_object::make_map());
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_EQ((*it).ptr()->parameterName, nullptr);
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
        EXPECT_EQ((*it).ptr()->parameterName, nullptr);
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
TEST(TestKeyIterator, TestNoRootKey)
{
    auto object = owned_object::make_map();
    object.emplace("root", owned_object::make_map({{"key", "value"}}));

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object.at(0), {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_EQ((*it).ptr()->parameterName, nullptr);
    EXPECT_STREQ((*it).as<const char *>(), "key");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "key");

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
        exclusion::object_set_ref exclude;
        ddwaf::key_iterator it(object, {}, exclude);

        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"root", {"root"}},
            {"key0", {"root", "key0"}},
            {"key0_0", {"root", "key0", "2", "key0_0"}},
            {"key1", {"root", "key1"}},
            {"key2", {"root", "key2"}},
            {"key2_0", {"root", "key2", "key2_0"}},
            {"key2_1", {"root", "key2", "key2_1"}},
            {"key2_2", {"root", "key2", "key2_2"}},
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

TEST(TestKeyIterator, TestMapNoScalars)
{
    auto object = owned_object::make_map();
    for (unsigned i = 0; i < 50; i++) { object.emplace("key", owned_object::make_map()); }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(object, {}, exclude);

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

TEST(TestKeyIterator, TestInvalidObjectPath)
{
    owned_object object;

    exclusion::object_set_ref exclude;
    std::vector<std::string> key_path{"key", "0", "value"};
    ddwaf::key_iterator it(object, key_path, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestSimplePath)
{
    auto object = owned_object::make_map({{"key", "value"}, {"key1", "value"}, {"key2", "value"}});

    {
        std::vector<std::string> key_path{"key"};
        ddwaf::key_iterator it(object, key_path, {});
        EXPECT_FALSE((bool)it);
        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0"};
        ddwaf::key_iterator it(object, key_path, {});
        EXPECT_FALSE((bool)it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0", "value"};
        ddwaf::key_iterator it(object, key_path, {});
        EXPECT_FALSE((bool)it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }
}

TEST(TestKeyIterator, TestMultiPath)
{
    auto object = owned_object::make_map(
        {{"first", owned_object::make_map({{"second", owned_object::make_map({{"third", "final"},
                                                          {"value", "value_third"}})},
                       {"value", "value_second"}})},
            {"value", "value_first"}});

    exclusion::object_set_ref exclude;
    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"second", {"first", "second"}},
            {"third", {"first", "second", "third"}},
            {"value", {"first", "second", "value"}},
            {"value", {"first", "value"}},
        };

        std::vector<std::string> key_path{"first"};
        ddwaf::key_iterator it(object, key_path, exclude);

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
            {"value", {"first", "second", "value"}},
        };

        std::vector<std::string> key_path{"first", "second"};
        ddwaf::key_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"first", "second", "third"};
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

    exclusion::object_set_ref exclude;
    {
        std::vector<std::string> key_path{"root", "key0"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_TRUE((bool)it);
        EXPECT_STREQ((*it).as<const char *>(), "key0_0");

        auto it_path = it.get_current_path();
        std::vector<std::string> path = {"root", "key0", "2", "key0_0"};
        EXPECT_EQ(it_path, path);

        EXPECT_FALSE(++it);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"root", "key1"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"key2_0", {"root", "key2", "key2_0"}},
            {"key2_1", {"root", "key2", "key2_1"}},
            {"key2_2", {"root", "key2", "key2_2"}},
        };

        std::vector<std::string> key_path{"root", "key2"};
        ddwaf::key_iterator it(object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as<const char *>(), value.c_str());

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

    exclusion::object_set_ref exclude;
    {
        std::vector<std::string> key_path{"rat"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"root", "cat"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"root", "key2", "key2_2", "0", "1", "2", "3"};
        ddwaf::key_iterator it(object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }
}

TEST(TestKeyIterator, TestExcludeSingleObject)
{
    auto object = owned_object::make_map({{"key", "value"}});

    std::unordered_set<object_view> persistent{object.at(0)};

    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::key_iterator it(object, {}, exclude);

    EXPECT_FALSE(it);
}

TEST(TestKeyIterator, TestExcludeMultipleObjects)
{
    auto root = owned_object::make_map({{"key", "value"}});

    auto map =
        root.emplace("other", owned_object::make_map({{"hello_key", "hello"}, {"bye_key", "bye"}}));

    std::unordered_set<object_view> persistent{root.at(0), map.at(1)};
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::key_iterator it(root, {}, exclude);

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

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestExcludeObjectInKeyPath)
{
    auto root = owned_object::make_map();
    auto child = root.emplace("parent", owned_object::make_map());
    child.emplace("child", "value");

    std::unordered_set<object_view> persistent{child.at(0)};
    exclusion::object_set_ref exclude{persistent, {}};
    std::vector<std::string> key_path{"parent", "child"};
    ddwaf::key_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}

TEST(TestKeyIterator, TestExcludeRootOfKeyPath)
{
    auto root = owned_object::make_map({{"parent", owned_object::make_map({{"child", "value"}})}});

    std::unordered_set<object_view> persistent{root.at(0)};
    exclusion::object_set_ref exclude{persistent, {}};
    std::vector<std::string> key_path{"parent", "child"};
    ddwaf::key_iterator it(root, key_path, exclude);

    EXPECT_FALSE(it);
}

} // namespace
