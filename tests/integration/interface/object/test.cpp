// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
#include "memory_resource.hpp"
#include "utils.hpp"

#include "common/gtest_utils.hpp"

#include <gtest/gtest.h>

using namespace ddwaf;

namespace {

std::string_view object_to_view(const ddwaf_object &o)
{
    std::size_t length = 0;
    const char *ptr = ddwaf_object_get_string(&o, &length);
    return {ptr, length};
}

TEST(TestObjectIntegration, TestCreateInvalid)
{
    ddwaf_object object;
    ddwaf_object_set_invalid(&object);
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_INVALID);

    // Getters
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_INVALID);
}

TEST(TestObjectIntegration, TestInvalidString)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object object;
    EXPECT_EQ(ddwaf_object_set_string(&object, nullptr, 0, alloc), nullptr);
    EXPECT_EQ(ddwaf_object_set_string(&object, nullptr, 0, alloc), nullptr);
}

TEST(TestObjectIntegration, TestString)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;
    ddwaf_object_set_string(&object, STRL("Sqreen"), alloc);

    EXPECT_TRUE((ddwaf_object_get_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_EQ(ddwaf_object_get_length(&object), 6);
    EXPECT_STRV(object_to_view(object), "Sqreen");

    // Getters
    EXPECT_TRUE((ddwaf_object_get_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STRV(object_to_view(object), "Sqreen");
    EXPECT_EQ(ddwaf_object_get_length(&object), 6);
    EXPECT_EQ(ddwaf_object_get_size(&object), 0);

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObjectIntegration, TestCreateStringl)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object object;
    ddwaf_object_set_string(&object, "Sqreen", sizeof("Sqreen") - 1, alloc);

    EXPECT_TRUE((ddwaf_object_get_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_EQ(ddwaf_object_get_length(&object), 6);
    EXPECT_STRV(object_to_view(object), "Sqreen");

    // Getters
    EXPECT_TRUE((ddwaf_object_get_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STRV(object_to_view(object), "Sqreen");
    EXPECT_EQ(ddwaf_object_get_length(&object), 6);
    EXPECT_EQ(ddwaf_object_get_size(&object), 0);

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObjectIntegration, TestCreateInt)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object object;
    ddwaf_object_set_signed(&object, INT64_MIN);

    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_SIGNED);

    // Getters
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_SIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), INT64_MIN);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
    EXPECT_EQ(ddwaf_object_get_bool(&object), false);

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObjectIntegration, TestCreateUint)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object object;
    ddwaf_object_set_unsigned(&object, UINT64_MAX);

    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_UNSIGNED);

    // Getters
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), UINT64_MAX);
    EXPECT_EQ(ddwaf_object_get_bool(&object), false);

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObjectIntegration, TestCreateBool)
{
    auto *alloc = ddwaf_get_default_allocator();
    {
        ddwaf_object object;
        ddwaf_object_set_bool(&object, true);

        EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_BOOL);

        // Getters
        EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_BOOL);
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
        EXPECT_EQ(ddwaf_object_get_bool(&object), true);

        ddwaf_object_destroy(&object, alloc);
    }

    {
        ddwaf_object object;
        ddwaf_object_set_bool(&object, false);

        EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_BOOL);

        // Getters
        EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_BOOL);
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
        EXPECT_EQ(ddwaf_object_get_bool(&object), false);

        ddwaf_object_destroy(&object, alloc);
    }
}

TEST(TestObjectIntegration, TestCreateArray)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object container;
    ddwaf_object_set_array(&container, 0, alloc);

    EXPECT_EQ(container.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(&container), 0);

    // Getters
    EXPECT_EQ(ddwaf_object_get_type(&container), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_length(&container), 0);
    EXPECT_EQ(ddwaf_object_get_size(&container), 0);
    EXPECT_EQ(ddwaf_object_at_value(&container, 0), nullptr);

    ddwaf_object_destroy(&container, alloc);
}

TEST(TestObjectIntegration, TestCreateMap)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object container;
    ddwaf_object_set_map(&container, 0, alloc);

    EXPECT_EQ(container.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(&container), 0);

    // Getters
    EXPECT_EQ(ddwaf_object_get_type(&container), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_length(&container), 0);
    EXPECT_EQ(ddwaf_object_get_size(&container), 0);
    EXPECT_EQ(ddwaf_object_at_value(&container, 0), nullptr);

    ddwaf_object_destroy(&container, alloc);
}

TEST(TestObjectIntegration, TestAddArray)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object container;
    ddwaf_object_set_array(&container, 3, alloc);

    ddwaf_object object;
    ddwaf_object_set_invalid(&object);

    // Test invalid parameters - these operations should be safe but have no effect
    // The new API doesn't have direct equivalents to these failure cases
    // but we can test similar scenarios

    ddwaf_object_insert(&container, alloc);
    ddwaf_object_set_signed(ddwaf_object_insert(&container, alloc), 42);
    ddwaf_object_set_unsigned(ddwaf_object_insert(&container, alloc), 43);

    EXPECT_EQ(container.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(&container), 3);

    EXPECT_EQ(ddwaf_object_get_type(ddwaf_object_at_value(&container, 0)), DDWAF_OBJ_INVALID);

    EXPECT_TRUE(
        (ddwaf_object_get_type(ddwaf_object_at_value(&container, 1)) & DDWAF_OBJ_SIGNED) != 0);
    EXPECT_EQ(ddwaf_object_get_signed(ddwaf_object_at_value(&container, 1)), 42);

    EXPECT_TRUE(
        (ddwaf_object_get_type(ddwaf_object_at_value(&container, 2)) & DDWAF_OBJ_UNSIGNED) != 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_at_value(&container, 2)), 43);

    // Getters
    EXPECT_EQ(ddwaf_object_get_type(&container), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_length(&container), 0);
    EXPECT_EQ(ddwaf_object_get_size(&container), 3);

    const auto *internal = ddwaf_object_at_value(&container, 0);
    EXPECT_EQ(ddwaf_object_get_type(internal), DDWAF_OBJ_INVALID);

    internal = ddwaf_object_at_value(&container, 1);
    EXPECT_TRUE((ddwaf_object_get_type(internal) & DDWAF_OBJ_SIGNED) != 0);
    EXPECT_EQ(ddwaf_object_get_signed(internal), 42);

    internal = ddwaf_object_at_value(&container, 2);
    EXPECT_TRUE((ddwaf_object_get_type(internal) & DDWAF_OBJ_UNSIGNED) != 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(internal), 43);

    EXPECT_EQ(ddwaf_object_at_value(&container, 3), nullptr);

    ddwaf_object_destroy(&container, alloc);
}

TEST(TestObjectIntegration, TestAddMap)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object map;
    ddwaf_object array;

    ddwaf_object_set_map(&map, 4, alloc);
    ddwaf_object_set_array(&array, 0, alloc);

    // Test setting values with the new API
    ddwaf_object_insert_key(&map, STRL("key"), alloc);
    EXPECT_STRV(object_to_view(map.via.map.ptr[0].key), "key");

    ddwaf_object_set_signed(ddwaf_object_insert_key(&map, STRL("key"), alloc), 42);
    EXPECT_STRV(object_to_view(map.via.map.ptr[1].key), "key");

    ddwaf_object_set_signed(ddwaf_object_insert_key(&map, "key2", 4, alloc), 43);
    EXPECT_STRV(object_to_view(map.via.map.ptr[2].key), "key2");

    char *str = static_cast<char *>(std::pmr::get_default_resource()->allocate(4, alignof(char)));
    // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
    memcpy(str, "key3", 4);
    ddwaf_object_set_signed(ddwaf_object_insert_key_nocopy(&map, str, 4, alloc), 44);
    EXPECT_EQ(object_to_view(map.via.map.ptr[3].key), "key3");

    // Getters
    EXPECT_EQ(ddwaf_object_get_type(&map), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_length(&map), 0);
    EXPECT_EQ(ddwaf_object_get_size(&map), 4);

    // size_t length;
    const auto *internal = ddwaf_object_at_value(&map, 0);
    EXPECT_EQ(ddwaf_object_get_type(internal), DDWAF_OBJ_INVALID);
    // EXPECT_STRV(ddwaf_object_get_key(internal, &length), "key");

    internal = ddwaf_object_at_value(&map, 1);
    EXPECT_TRUE((ddwaf_object_get_type(internal) & DDWAF_OBJ_SIGNED) != 0);
    EXPECT_EQ(ddwaf_object_get_signed(internal), 42);
    // EXPECT_STRV(ddwaf_object_get_key(internal, &length), "key");
    // EXPECT_EQ(length, 3);

    internal = ddwaf_object_at_value(&map, 2);
    EXPECT_TRUE((ddwaf_object_get_type(internal) & DDWAF_OBJ_SIGNED) != 0);
    EXPECT_EQ(ddwaf_object_get_signed(internal), 43);
    ////EXPECT_STRV(ddwaf_object_get_key(internal, &length), "key2");
    // EXPECT_EQ(length, 4);

    internal = ddwaf_object_at_value(&map, 3);
    EXPECT_TRUE((ddwaf_object_get_type(internal) & DDWAF_OBJ_SIGNED) != 0);
    EXPECT_EQ(ddwaf_object_get_signed(internal), 44);
    // EXPECT_STRV(ddwaf_object_get_key(internal, &length), "key3");
    // EXPECT_EQ(length, 4);

    EXPECT_EQ(ddwaf_object_at_value(&map, 4), nullptr);

    ddwaf_object_destroy(&map, alloc);
    ddwaf_object_destroy(&array, alloc);
}

TEST(TestObjectIntegration, NullFree)
{
    ddwaf_object_destroy(nullptr, ddwaf_get_default_allocator());
}

TEST(TestObjectIntegration, FindNullObject)
{
    EXPECT_EQ(ddwaf_object_find(nullptr, STRL("key")), nullptr);
}

TEST(TestObjectIntegration, FindInvalidKey)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_insert_key(&map, STRL("key"), alloc);

    EXPECT_EQ(ddwaf_object_find(&map, nullptr, 1), nullptr);
    EXPECT_EQ(ddwaf_object_find(&map, "", 0), nullptr);

    ddwaf_object_destroy(&map, alloc);
}

TEST(TestObjectIntegration, FindNotMap)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object array;
    ddwaf_object_set_array(&array, 1, alloc);
    ddwaf_object_insert(&array, alloc);

    EXPECT_EQ(ddwaf_object_find(&array, STRL("key")), nullptr);

    ddwaf_object_destroy(&array, alloc);
}

TEST(TestObjectIntegration, FindEmptyMap)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_unsigned(ddwaf_object_insert_key(&map, STRL("key"), alloc), 42);

    const auto *object = ddwaf_object_find(&map, STRL("key"));
    ASSERT_NE(object, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(object), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_unsigned(object), 42);

    ddwaf_object_destroy(&map, alloc);
}

} // namespace
