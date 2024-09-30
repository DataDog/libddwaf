// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "context_allocator.hpp"
#include "iterator.hpp"
#include "test_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestKeyIterator, TestInvalidIterator)
{
    ddwaf_object object;
    ddwaf_object_invalid(&object);

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestStringScalar)
{
    ddwaf_object object;
    ddwaf_object_string(&object, "value");

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestUnsignedScalar)
{
    ddwaf_object object;
    ddwaf_object_unsigned(&object, 22);

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestSignedScalar)
{
    ddwaf_object object;
    ddwaf_object_signed(&object, 22);

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestArraySingleItem)
{
    ddwaf_object object, tmp;
    ddwaf_object_array(&object);
    ddwaf_object_array_add(&object, ddwaf_object_string(&tmp, "string"));

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestArrayMultipleItems)
{
    ddwaf_object object, tmp;
    ddwaf_object_array(&object);
    for (unsigned i = 0; i < 50; i++) {
        ddwaf_object_array_add(&object, ddwaf_object_string(&tmp, std::to_string(i).c_str()));
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestArrayPastSizeLimit)
{
    ddwaf::object_limits limits;
    ddwaf_object object, tmp;
    ddwaf_object_array(&object);

    for (unsigned i = 0; i < limits.max_container_size + 50; i++) {
        ddwaf_object_array_add(&object, ddwaf_object_string(&tmp, std::to_string(i).c_str()));
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestDeepArray)
{
    ddwaf_object *array;
    ddwaf_object object;

    ddwaf_object_array(&object);
    array = &object;

    for (unsigned i = 0; i < 10; i++) {
        ddwaf_object intermediate, tmp;
        auto index = std::to_string(i);

        ddwaf_object_array(&intermediate);
        ddwaf_object_array_add(array, ddwaf_object_string(&tmp, ("val" + index).c_str()));
        ddwaf_object_array_add(array, &intermediate);

        array = &array->array[1];
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestDeepArrayPastLimit)
{
    ddwaf::object_limits limits;
    ddwaf_object *array;
    ddwaf_object object;

    ddwaf_object_array(&object);
    array = &object;

    for (unsigned i = 0; i < limits.max_container_depth + 10; i++) {
        ddwaf_object intermediate, tmp;
        auto index = std::to_string(i);

        ddwaf_object_array(&intermediate);
        ddwaf_object_array_add(array, ddwaf_object_string(&tmp, ("val" + index).c_str()));
        ddwaf_object_array_add(array, &intermediate);

        array = &array->array[1];
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestArrayNoScalars)
{
    ddwaf_object object, tmp;
    ddwaf_object_array(&object);
    for (unsigned i = 0; i < 50; i++) { ddwaf_object_array_add(&object, ddwaf_object_array(&tmp)); }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);

    EXPECT_FALSE((bool)it);
    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestMapSingleItem)
{
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "key", ddwaf_object_string(&tmp, "value"));

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_EQ((*it).ptr()->parameterName, nullptr);
    EXPECT_STREQ((*it).as_unchecked<const char *>(), "key");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "key");

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestMapMultipleItems)
{
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;
        ddwaf_object_map_add(&object, key.c_str(), ddwaf_object_string(&tmp, value.c_str()));
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;

        EXPECT_TRUE((bool)it);
        EXPECT_STREQ((*it).as_unchecked<const char *>(), key.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), key.c_str());
        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestMapMultipleNullAndInvalid)
{
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);

    for (unsigned i = 0; i < 25; i++) {
        {
            auto index = std::to_string(i * 3);
            std::string key = "key" + index;
            std::string value = "value" + index;
            ddwaf_object_map_add(&object, key.c_str(), ddwaf_object_string(&tmp, value.c_str()));
        }

        {
            auto index = std::to_string(i * 3 + 1);
            std::string key = "key" + index;
            ddwaf_object_map_add(&object, key.c_str(), ddwaf_object_null(&tmp));
        }

        {
            auto index = std::to_string(i * 3 + 2);
            std::string key = "key" + index;
            ddwaf_object_map_add(&object, key.c_str(), ddwaf_object_invalid(&tmp));
        }
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);

    for (unsigned i = 0; i < 25; i++) {
        {
            auto index = std::to_string(i * 3);
            std::string key = "key" + index;

            EXPECT_TRUE((bool)it);
            EXPECT_STREQ((*it).as_unchecked<const char *>(), key.c_str());

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

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestMapPastSizeLimit)
{
    ddwaf::object_limits limits;
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);

    for (unsigned i = 0; i < limits.max_container_size + 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;
        ddwaf_object_map_add(&object, key.c_str(), ddwaf_object_string(&tmp, value.c_str()));
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);

    for (unsigned i = 0; i < limits.max_container_size; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;

        EXPECT_TRUE((bool)it);
        EXPECT_STREQ((*it).as_unchecked<const char *>(), key.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), key.c_str());
        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestDeepMap)
{
    ddwaf_object *map;
    ddwaf_object object;

    ddwaf_object_map(&object);
    map = &object;

    for (unsigned i = 0; i < 10; i++) {
        ddwaf_object intermediate, tmp;
        auto index = std::to_string(i);

        ddwaf_object_map(&intermediate);
        ddwaf_object_map_add(
            map, ("str" + index).c_str(), ddwaf_object_string(&tmp, ("val" + index).c_str()));
        ddwaf_object_map_add(map, ("map" + index).c_str(), &intermediate);

        map = &map->array[1];
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);

    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_EQ((*it).ptr()->parameterName, nullptr);
        EXPECT_STREQ((*it).as_unchecked<const char *>(), ("str" + index).c_str());

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
        EXPECT_STREQ((*it).as_unchecked<const char *>(), ("map" + index).c_str());

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

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestMapPastDepthLimit)
{
    ddwaf::object_limits limits;
    ddwaf_object *map;
    ddwaf_object object;

    ddwaf_object_map(&object);
    map = &object;

    for (unsigned i = 0; i < limits.max_container_depth + 10; i++) {
        ddwaf_object intermediate, tmp;
        auto index = std::to_string(i);

        ddwaf_object_map(&intermediate);
        ddwaf_object_map_add(
            map, ("str" + index).c_str(), ddwaf_object_string(&tmp, ("val" + index).c_str()));
        ddwaf_object_map_add(map, ("map" + index).c_str(), &intermediate);

        map = &map->array[1];
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);

    for (unsigned i = 0; i < limits.max_container_depth; i++) {
        auto index = std::to_string(i);

        EXPECT_EQ((*it).ptr()->parameterName, nullptr);
        EXPECT_STREQ((*it).as_unchecked<const char *>(), ("str" + index).c_str());

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
        EXPECT_STREQ((*it).as_unchecked<const char *>(), ("map" + index).c_str());

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

    ddwaf_object_free(&object);
}

// Ensure the key on the root object is not reported.
// This key will usually correspond to one of the provided
// addesses (e.g. server.request.query).
TEST(TestKeyIterator, TestNoRootKey)
{
    ddwaf_object root, object, tmp;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "key", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "root", &object);

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&root.array[0], {}, exclude);
    EXPECT_TRUE((bool)it);
    EXPECT_EQ((*it).ptr()->parameterName, nullptr);
    EXPECT_STREQ((*it).as_unchecked<const char *>(), "key");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "key");

    EXPECT_FALSE(++it);

    ddwaf_object_free(&root);
}

TEST(TestKeyIterator, TestContainerMix)
{
    ddwaf_object object = yaml_to_object(R"(
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
        ddwaf::key_iterator it(&object, {}, exclude);

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
            EXPECT_STREQ((*it).as_unchecked<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestMapNoScalars)
{
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);
    for (unsigned i = 0; i < 50; i++) {
        ddwaf_object_map_add(&object, "key", ddwaf_object_map(&tmp));
    }

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&object, {}, exclude);

    for (unsigned i = 0; i < 50; i++) {
        EXPECT_TRUE((bool)it);
        EXPECT_STREQ((*it).as_unchecked<const char *>(), "key");

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), "key");
        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestInvalidObjectPath)
{
    ddwaf_object object;
    ddwaf_object_invalid(&object);

    exclusion::object_set_ref exclude;
    std::vector<std::string> key_path{"key", "0", "value"};
    ddwaf::key_iterator it(&object, key_path, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestSimplePath)
{
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);

    ddwaf_object_map_add(&object, "key", ddwaf_object_string(&tmp, "value"));
    ddwaf_object_map_add(&object, "key1", ddwaf_object_string(&tmp, "value"));
    ddwaf_object_map_add(&object, "key2", ddwaf_object_string(&tmp, "value"));

    {
        std::vector<std::string> key_path{"key"};
        ddwaf::key_iterator it(&object, key_path, {});
        EXPECT_FALSE((bool)it);
        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0"};
        ddwaf::key_iterator it(&object, key_path, {});
        EXPECT_FALSE((bool)it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::string> key_path{"key", "0", "value"};
        ddwaf::key_iterator it(&object, key_path, {});
        EXPECT_FALSE((bool)it);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        EXPECT_FALSE(++it);
    }

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestMultiPath)
{
    ddwaf_object object, *map, tmp;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "first", ddwaf_object_map(&tmp));
    ddwaf_object_map_add(&object, "value", ddwaf_object_string(&tmp, "value_first"));

    map = &object.array[0];
    ddwaf_object_map_add(map, "second", ddwaf_object_map(&tmp));
    ddwaf_object_map_add(map, "value", ddwaf_object_string(&tmp, "value_second"));

    map = &map->array[0];
    ddwaf_object_map_add(map, "third", ddwaf_object_string(&tmp, "final"));
    ddwaf_object_map_add(map, "value", ddwaf_object_string(&tmp, "value_third"));

    exclusion::object_set_ref exclude;
    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"second", {"first", "second"}},
            {"third", {"first", "second", "third"}},
            {"value", {"first", "second", "value"}},
            {"value", {"first", "value"}},
        };

        std::vector<std::string> key_path{"first"};
        ddwaf::key_iterator it(&object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as_unchecked<const char *>(), value.c_str());

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
        ddwaf::key_iterator it(&object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as_unchecked<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"first", "second", "third"};
        ddwaf::key_iterator it(&object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestContainerMixPath)
{
    ddwaf_object object = yaml_to_object(R"(
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
        ddwaf::key_iterator it(&object, key_path, exclude);
        EXPECT_TRUE((bool)it);
        EXPECT_STREQ((*it).as_unchecked<const char *>(), "key0_0");

        auto it_path = it.get_current_path();
        std::vector<std::string> path = {"root", "key0", "2", "key0_0"};
        EXPECT_EQ(it_path, path);

        EXPECT_FALSE(++it);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"root", "key1"};
        ddwaf::key_iterator it(&object, key_path, exclude);
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
        ddwaf::key_iterator it(&object, key_path, exclude);

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it).as_unchecked<const char *>(), value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE((bool)it);
    }

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestContainerMixInvalidPath)
{
    ddwaf_object object = yaml_to_object(R"(
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
        ddwaf::key_iterator it(&object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"root", "cat"};
        ddwaf::key_iterator it(&object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    {
        std::vector<std::string> key_path{"root", "key2", "key2_2", "0", "1", "2", "3"};
        ddwaf::key_iterator it(&object, key_path, exclude);
        EXPECT_FALSE((bool)it);
    }

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestMapDepthLimitPath)
{
    ddwaf::object_limits limits;

    ddwaf_object object = yaml_to_object(R"(
        {
            root: {
                child: {
                    grandchild: {
                        unknown: {
                            key: value
                        },
                        another: value
                    }
                }
            }
        }
    )");

    exclusion::object_set_ref exclude;
    {
        limits.max_container_depth = 3;
        std::vector<std::string> key_path{"root", "child", "grandchild"};
        ddwaf::key_iterator it(&object, key_path, exclude, limits);

        EXPECT_FALSE(it);
    }

    {
        limits.max_container_depth = 4;
        std::vector<std::string> key_path{"root", "child", "grandchild"};
        ddwaf::key_iterator it(&object, key_path, exclude, limits);

        EXPECT_TRUE(it);
        {
            auto it_path = it.get_current_path();
            std::vector<std::string> path = {"root", "child", "grandchild", "unknown"};
            EXPECT_EQ(it_path, path);
        }

        EXPECT_TRUE(++it);
        {
            auto it_path = it.get_current_path();
            std::vector<std::string> path = {"root", "child", "grandchild", "another"};
            EXPECT_EQ(it_path, path);
        }

        EXPECT_FALSE(++it);
    }

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestInvalidMap)
{
    ddwaf_object tmp, root = DDWAF_OBJECT_MAP;

    exclusion::object_set_ref exclude;
    root.nbEntries = 30;
    {
        ddwaf::key_iterator it(&root, {}, exclude);
        EXPECT_FALSE(it);
    }

    root.nbEntries = 0;
    ddwaf_object_map_add(&root, "key", ddwaf_object_string(&tmp, "value"));
    root.nbEntries = 0;

    {
        ddwaf::key_iterator it(&root, {}, exclude);
        EXPECT_FALSE(it);
    }
    root.nbEntries = 1;

    ddwaf_object_map_add(&root, "other", ddwaf_object_map(&tmp));
    root.array[1].nbEntries = 30;
    {
        ddwaf::key_iterator it(&root, {}, exclude);
        EXPECT_TRUE(it);
        EXPECT_TRUE(++it);
        EXPECT_FALSE(++it);
    }

    ddwaf_object_free(&root);
}

TEST(TestKeyeIterator, TestInvalidMapKey)
{
    exclusion::object_set_ref exclude;
    ddwaf_object tmp, root = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&root, "key", ddwaf_object_string(&tmp, "value"));

    free((void *)root.array[0].parameterName);
    root.array[0].parameterName = nullptr;

    {
        ddwaf::key_iterator it(&root, {}, exclude);
        EXPECT_FALSE(it);
    }

    ddwaf_object_map_add(&root, "other", ddwaf_object_string(&tmp, "value"));
    {
        ddwaf::key_iterator it(&root, {}, exclude);
        EXPECT_TRUE(it);
        EXPECT_FALSE(++it);
    }

    ddwaf_object_free(&root);
}

TEST(TestKeyIterator, TestInvalidMapKeyWithPath)
{
    ddwaf_object tmp, other, root = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&root, "key", ddwaf_object_string(&tmp, "value"));

    free((void *)root.array[0].parameterName);
    root.array[0].parameterName = nullptr;

    exclusion::object_set_ref exclude;
    {
        std::vector<std::string> key_path{"key"};
        ddwaf::key_iterator it(&root, key_path, exclude);
        EXPECT_FALSE(it);
    }

    ddwaf_object_map(&other);
    ddwaf_object_map_add(&other, "key", ddwaf_object_string(&tmp, "value"));
    ddwaf_object_map_add(&root, "other", &other);

    {
        std::vector<std::string> key_path{"other"};
        ddwaf::key_iterator it(&root, key_path, exclude);
        EXPECT_TRUE(it);
        EXPECT_FALSE(++it);
    }

    ddwaf_object_free(&root);
}

TEST(TestKeyIterator, TestRecursiveMap)
{
    ddwaf_object root;
    root.nbEntries = 1;
    root.parameterName = "Sqreen";
    root.parameterNameLength = sizeof("Sqreen") - 1;
    root.type = DDWAF_OBJ_MAP;
    root.array = &root;

    exclusion::object_set_ref exclude;
    ddwaf::key_iterator it(&root, {}, exclude);
    EXPECT_TRUE(it);
    EXPECT_FALSE(++it);
}

TEST(TestKeyIterator, TestExcludeSingleObject)
{
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "key", ddwaf_object_string(&tmp, "value"));

    std::unordered_set<const ddwaf_object *> persistent{&object.array[0]};

    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::key_iterator it(&object, {}, exclude);

    EXPECT_FALSE(it);

    ddwaf_object_free(&object);
}

TEST(TestKeyIterator, TestExcludeMultipleObjects)
{
    ddwaf_object root, map, tmp;
    ddwaf_object_map(&map);
    ddwaf_object_map_add(&map, "hello_key", ddwaf_object_string(&tmp, "hello"));
    ddwaf_object_map_add(&map, "bye_key", ddwaf_object_string(&tmp, "bye"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "key", ddwaf_object_string(&tmp, "value"));
    ddwaf_object_map_add(&root, "other", &map);

    std::unordered_set<const ddwaf_object *> persistent{&root.array[0], &map.array[1]};
    exclusion::object_set_ref exclude{persistent, {}};
    ddwaf::key_iterator it(&root, {}, exclude);

    EXPECT_TRUE(it);
    EXPECT_STREQ((*it).as_unchecked<const char *>(), "other");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "other");

    EXPECT_STREQ((*it).as_unchecked<const char *>(), "other");

    EXPECT_TRUE(++it);
    EXPECT_STREQ((*it).as_unchecked<const char *>(), "hello_key");

    path = it.get_current_path();
    EXPECT_EQ(path.size(), 2);
    EXPECT_STREQ(path[0].c_str(), "other");
    EXPECT_STREQ(path[1].c_str(), "hello_key");

    EXPECT_FALSE(++it);

    ddwaf_object_free(&root);
}

TEST(TestKeyIterator, TestExcludeObjectInKeyPath)
{
    ddwaf_object root, child, tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "child", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "parent", &child);

    std::unordered_set<const ddwaf_object *> persistent{&child.array[0]};
    exclusion::object_set_ref exclude{persistent, {}};
    std::vector<std::string> key_path{"parent", "child"};
    ddwaf::key_iterator it(&root, key_path, exclude);

    EXPECT_FALSE(it);

    ddwaf_object_free(&root);
}

TEST(TestKeyIterator, TestExcludeRootOfKeyPath)
{
    ddwaf_object root, child, tmp;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "child", ddwaf_object_string(&tmp, "value"));

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "parent", &child);

    std::unordered_set<const ddwaf_object *> persistent{&root.array[0]};
    exclusion::object_set_ref exclude{persistent, {}};
    std::vector<std::string> key_path{"parent", "child"};
    ddwaf::key_iterator it(&root, key_path, exclude);

    EXPECT_FALSE(it);

    ddwaf_object_free(&root);
}

} // namespace
