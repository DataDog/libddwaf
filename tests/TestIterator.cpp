// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestIterator, TestInvalidIterator)
{
    ddwaf_object object;
    ddwaf_object_invalid(&object);

    ddwaf::object_iterator it(&object);
    EXPECT_FALSE(it.is_valid());

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestIterator, TestStringScalar)
{
    ddwaf_object object;
    ddwaf_object_string(&object, "value");

    ddwaf::object_iterator it(&object);
    EXPECT_TRUE(it.is_valid());
    EXPECT_EQ(*it, &object);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestUnsignedScalar)
{
    ddwaf_object object;
    ddwaf_object_unsigned_force(&object, 22);

    ddwaf::object_iterator it(&object);
    EXPECT_TRUE(it.is_valid());
    EXPECT_EQ(*it, &object);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestIterator, TestSignedScalar)
{
    ddwaf_object object;
    ddwaf_object_signed_force(&object, 22);

    ddwaf::object_iterator it(&object);
    EXPECT_TRUE(it.is_valid());
    EXPECT_EQ(*it, &object);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestIterator, TestArraySingleItem)
{
    ddwaf_object object, tmp;
    ddwaf_object_array(&object);
    ddwaf_object_array_add(&object, ddwaf_object_string(&tmp, "string"));

    ddwaf::object_iterator it(&object);
    EXPECT_TRUE(it.is_valid());
    EXPECT_STREQ((*it)->stringValue, "string");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "0");

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestArrayMultipleItems)
{
    ddwaf_object object, tmp;
    ddwaf_object_array(&object);
    for (unsigned i = 0; i < 50; i++) {
        ddwaf_object_array_add(&object,
            ddwaf_object_string(&tmp, std::to_string(i).c_str()));
    }

    ddwaf::object_iterator it(&object);

    unsigned index = 0;
    do {
        auto index_str = std::to_string(index);
        EXPECT_TRUE(it.is_valid());
        EXPECT_STREQ((*it)->stringValue, index_str.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), index_str.c_str());
        ++index;
    } while (++it);

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestArrayPastSizeLimit)
{
    ddwaf::object_limits limits;
    ddwaf_object object, tmp;
    ddwaf_object_array(&object);

    for (unsigned i = 0; i < limits.max_container_size + 50; i++) {
        ddwaf_object_array_add(&object,
            ddwaf_object_string(&tmp, std::to_string(i).c_str()));
    }

    ddwaf::object_iterator it(&object);

    for (unsigned i = 0; i < limits.max_container_size; i++) {
        auto index_str = std::to_string(i);
        EXPECT_TRUE(it.is_valid());
        EXPECT_STREQ((*it)->stringValue, index_str.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), index_str.c_str());

        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestDeepArray)
{
    ddwaf_object *array;
    ddwaf_object object;

    ddwaf_object_array(&object);
    array = &object;

    for (unsigned i = 0; i < 10; i++) {
        ddwaf_object intermediate, tmp;
        auto index = std::to_string(i);

        ddwaf_object_array(&intermediate);
        ddwaf_object_array_add(array,
                ddwaf_object_string(&tmp, ("val" + index).c_str()));
        ddwaf_object_array_add(array, &intermediate);

        array = &array->array[1];
    }

    ddwaf::object_iterator it(&object);
    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_STREQ((*it)->stringValue, ("val" + index).c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), i + 1);

        for (unsigned j = 0; j < i; j++) {
            EXPECT_STREQ(path[j].c_str(), "1");
        }
        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestDeepArrayPastLimit)
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
        ddwaf_object_array_add(array,
                ddwaf_object_string(&tmp, ("val" + index).c_str()));
        ddwaf_object_array_add(array, &intermediate);

        array = &array->array[1];
    }

    ddwaf::object_iterator it(&object);
    for (unsigned i = 0; i < limits.max_container_depth; i++) {
        auto index = std::to_string(i);

        EXPECT_STREQ((*it)->stringValue, ("val" + index).c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), i + 1);

        for (unsigned j = 0; j < i; j++) {
            EXPECT_STREQ(path[j].c_str(), "1");
        }
        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestArrayNoScalars)
{
    ddwaf_object object, tmp;
    ddwaf_object_array(&object);
    for (unsigned i = 0; i < 50; i++) {
        ddwaf_object_array_add(&object, ddwaf_object_array(&tmp));
    }

    ddwaf::object_iterator it(&object);

    EXPECT_FALSE(it.is_valid());
    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestMapSingleItem)
{
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);
    ddwaf_object_map_add(&object, "key", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_iterator it(&object);

    EXPECT_TRUE(it.is_valid());
    EXPECT_STREQ((*it)->stringValue, "value");
    EXPECT_STREQ((*it)->parameterName, "key");

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 1);
    EXPECT_STREQ(path[0].c_str(), "key");

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestMapMultipleItems)
{
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;
        ddwaf_object_map_add(&object, key.c_str(),
            ddwaf_object_string(&tmp, value.c_str()));
    }

    ddwaf::object_iterator it(&object);

    for (unsigned i = 0; i < 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;

        EXPECT_TRUE(it.is_valid());
        EXPECT_STREQ((*it)->stringValue, value.c_str());
        EXPECT_STREQ((*it)->parameterName, key.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), key.c_str());
        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestMapPastSizeLimit)
{
    ddwaf::object_limits limits;
    ddwaf_object object, tmp;
    ddwaf_object_map(&object);

    for (unsigned i = 0; i < limits.max_container_size + 50; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;
        ddwaf_object_map_add(&object, key.c_str(),
            ddwaf_object_string(&tmp, value.c_str()));
    }

    ddwaf::object_iterator it(&object);

    for (unsigned i = 0; i < limits.max_container_size; i++) {
        auto index = std::to_string(i);
        std::string key = "key" + index;
        std::string value = "value" + index;

        EXPECT_TRUE(it.is_valid());
        EXPECT_STREQ((*it)->stringValue, value.c_str());
        EXPECT_STREQ((*it)->parameterName, key.c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 1);
        EXPECT_STREQ(path[0].c_str(), key.c_str());
        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestDeepMap)
{
    ddwaf_object *map;
    ddwaf_object object;

    ddwaf_object_map(&object);
    map = &object;

    for (unsigned i = 0; i < 10; i++) {
        ddwaf_object intermediate, tmp;
        auto index = std::to_string(i);

        ddwaf_object_map(&intermediate);
        ddwaf_object_map_add(map, ("str" + index).c_str(),
                ddwaf_object_string(&tmp, ("val" + index).c_str()));
        ddwaf_object_map_add(map, ("map" + index).c_str(), &intermediate);

        map = &map->array[1];
    }

    ddwaf::object_iterator it(&object);
    for (unsigned i = 0; i < 10; i++) {
        auto index = std::to_string(i);

        EXPECT_STREQ((*it)->parameterName, ("str" + index).c_str());
        EXPECT_STREQ((*it)->stringValue, ("val" + index).c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), i + 1);

        for (unsigned j = 0; j < i; j++) {
            EXPECT_STREQ(path[j].c_str(), ("map" + std::to_string(j)).c_str());
        }
        EXPECT_STREQ(path.back().c_str(), ("str" + index).c_str());
        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestMapPastDepthLimit)
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
        ddwaf_object_map_add(map, ("str" + index).c_str(),
                ddwaf_object_string(&tmp, ("val" + index).c_str()));
        ddwaf_object_map_add(map, ("map" + index).c_str(), &intermediate);

        map = &map->array[1];
    }

    ddwaf::object_iterator it(&object);
    for (unsigned i = 0; i < limits.max_container_depth; i++) {
        auto index = std::to_string(i);

        EXPECT_STREQ((*it)->parameterName, ("str" + index).c_str());
        EXPECT_STREQ((*it)->stringValue, ("val" + index).c_str());

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), i + 1);

        for (unsigned j = 0; j < i; j++) {
            EXPECT_STREQ(path[j].c_str(), ("map" + std::to_string(j)).c_str());
        }
        EXPECT_STREQ(path.back().c_str(), ("str" + index).c_str());
        ++it;
    }

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestContainerMix)
{
    ddwaf_object object = readRule(R"(
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
        ddwaf::object_iterator it(&object, {"root"});

        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"value0_0", {"root", "key0", "0"}},
            {"value0_1", {"root", "key0", "1"}},
            {"value0_2", {"root", "key0", "2", "key0_0"}},
            {"value0_3", {"root", "key0", "3"}},
            {"value1_0", {"root", "key1"}},
            {"value2_0", {"root", "key2", "key2_0"}},
            {"value2_1", {"root", "key2", "key2_1"}},
            {"value2_2", {"root", "key2", "key2_2", "0"}},
            {"value2_3", {"root", "key2", "key2_2", "1"}}
        };

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it)->stringValue, value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE(it.is_valid());
    }

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestMapNoScalars)
{
    ddwaf_object object, tmp;
    ddwaf_object_array(&object);
    for (unsigned i = 0; i < 50; i++) {
        ddwaf_object_map_add(&object, "key", ddwaf_object_map(&tmp));
    }

    ddwaf::object_iterator it(&object);

    EXPECT_FALSE(it.is_valid());
    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestIterator, TestInvalidObjectPath)
{
    ddwaf_object object;
    ddwaf_object_invalid(&object);

    ddwaf::object_iterator it(&object, {"key", "0", "value"});
    EXPECT_FALSE(it.is_valid());

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestIterator, TestContainerMixPath)
{
    ddwaf_object object = readRule(R"(
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
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"value0_0", {"root", "key0", "0"}},
            {"value0_1", {"root", "key0", "1"}},
            {"value0_2", {"root", "key0", "2", "key0_0"}},
            {"value0_3", {"root", "key0", "3"}},
        };

        ddwaf::object_iterator it(&object, {"root", "key0"});

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it)->stringValue, value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE(it.is_valid());
    }

    {
        ddwaf::object_iterator it(&object, {"root", "key1"});
        EXPECT_STREQ((*it)->stringValue, "value1_0");

        auto it_path = it.get_current_path();
        std::vector<std::string> path = {"root", "key1"};
        EXPECT_EQ(it_path, path);
        EXPECT_FALSE(++it);
    }

    {
        std::vector<std::pair<std::string, std::vector<std::string>>> values = {
            {"value2_0", {"root", "key2", "key2_0"}},
            {"value2_1", {"root", "key2", "key2_1"}},
            {"value2_2", {"root", "key2", "key2_2", "0"}},
            {"value2_3", {"root", "key2", "key2_2", "1"}}
        };

        ddwaf::object_iterator it(&object, {"root", "key2"});

        for (auto &[value, path] : values) {
            EXPECT_STREQ((*it)->stringValue, value.c_str());

            auto it_path = it.get_current_path();
            EXPECT_EQ(path, it_path);
            ++it;
        }

        EXPECT_FALSE(it.is_valid());
    }

    {
        ddwaf::object_iterator it(&object, {"rat"});
        EXPECT_FALSE(it.is_valid());
    }

    {
        ddwaf::object_iterator it(&object, {"root", "cat"});
        EXPECT_FALSE(it.is_valid());
    }


    ddwaf_object_free(&object);
}

TEST(TestIterator, TestContainerMixInvalidPath)
{
    ddwaf_object object = readRule(R"(
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
        ddwaf::object_iterator it(&object, {"rat"});
        EXPECT_FALSE(it.is_valid());
    }

    {
        ddwaf::object_iterator it(&object, {"root", "cat"});
        EXPECT_FALSE(it.is_valid());
    }

    {
        ddwaf::object_iterator it(&object, {"root", "key2", "key2_2", "0", "1", "2", "3"});
        EXPECT_FALSE(it.is_valid());
    }

    ddwaf_object_free(&object);
}


