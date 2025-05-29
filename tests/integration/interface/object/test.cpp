// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
#include "utils.hpp"

#include "common/gtest_utils.hpp"

#include <gtest/gtest.h>

using namespace ddwaf;

namespace {

TEST(TestObjectIntegration, TestCreateInvalid)
{
    ddwaf_object object;
    ddwaf_object_invalid(&object);
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_INVALID);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_INVALID);
}

TEST(TestObjectIntegration, TestInvalidString)
{
    ddwaf_object object;
    EXPECT_EQ(ddwaf_object_string(&object, nullptr), nullptr);
    EXPECT_EQ(ddwaf_object_stringl(&object, nullptr, 0), nullptr);
}

TEST(TestObjectIntegration, TestString)
{

    ddwaf_object object;
    ddwaf_object_string(&object, "Sqreen");

    EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_EQ(ddwaf_object_length(&object), 6);
    EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "Sqreen");

    // Getters
    size_t length;
    EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STREQ(ddwaf_object_get_string(&object, &length), "Sqreen");
    EXPECT_EQ(length, 6);
    EXPECT_EQ(ddwaf_object_length(&object), 6);
    EXPECT_EQ(ddwaf_object_size(&object), 0);

    ddwaf_object_free(&object);
}

TEST(TestObjectIntegration, TestCreateStringl)
{
    ddwaf_object object;
    ddwaf_object_stringl(&object, "Sqreen", sizeof("Sqreen") - 1);

    EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_EQ(ddwaf_object_length(&object), 6);
    EXPECT_STREQ((const char *)ddwaf_object_get_string(&object, nullptr), "Sqreen");

    // Getters
    size_t length;
    EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STREQ(ddwaf_object_get_string(&object, &length), "Sqreen");
    EXPECT_EQ(length, 6);
    EXPECT_EQ(ddwaf_object_length(&object), 6);
    EXPECT_EQ(ddwaf_object_size(&object), 0);

    ddwaf_object_free(&object);
}

TEST(TestObjectIntegration, TestCreateInt)
{
    {
        ddwaf_object object;
        ddwaf_object_string_from_signed(&object, INT64_MIN);

        EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
        EXPECT_EQ(ddwaf_object_length(&object), 20);
        EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "-9223372036854775808");

        // Getters
        EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
        EXPECT_EQ(ddwaf_object_length(&object), 20);
        EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "-9223372036854775808");
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
        EXPECT_EQ(ddwaf_object_get_bool(&object), false);

        ddwaf_object_free(&object);
    }

    {
        ddwaf_object object;
        ddwaf_object_string_from_signed(&object, INT64_MAX);

        EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
        EXPECT_EQ(ddwaf_object_length(&object), 19);
        EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "9223372036854775807");

        // Getters
        EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
        EXPECT_EQ(ddwaf_object_length(&object), 19);
        EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "9223372036854775807");
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
        EXPECT_EQ(ddwaf_object_get_bool(&object), false);

        ddwaf_object_free(&object);
    }
}

TEST(TestObjectIntegration, TestCreateIntForce)
{
    ddwaf_object object;
    ddwaf_object_signed(&object, INT64_MIN);

    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_SIGNED);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_SIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), INT64_MIN);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
    EXPECT_EQ(ddwaf_object_get_bool(&object), false);

    ddwaf_object_free(&object);
}

TEST(TestObjectIntegration, TestCreateUint)
{
    ddwaf_object object;
    ddwaf_object_string_from_unsigned(&object, UINT64_MAX);

    EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_EQ(ddwaf_object_length(&object), 20);
    EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "18446744073709551615");

    // Getters
    EXPECT_TRUE((ddwaf_object_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_EQ(ddwaf_object_length(&object), 20);
    EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "18446744073709551615");
    EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
    EXPECT_EQ(ddwaf_object_get_bool(&object), false);

    ddwaf_object_free(&object);
}

TEST(TestObjectIntegration, TestCreateUintForce)
{
    ddwaf_object object;
    ddwaf_object_unsigned(&object, UINT64_MAX);

    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_UNSIGNED);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), UINT64_MAX);
    EXPECT_EQ(ddwaf_object_get_bool(&object), false);

    ddwaf_object_free(&object);
}

TEST(TestObjectIntegration, TestCreateBool)
{
    {
        ddwaf_object object;
        ddwaf_object_bool(&object, true);

        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_BOOL);

        // Getters
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_BOOL);
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
        EXPECT_EQ(ddwaf_object_get_bool(&object), true);

        ddwaf_object_free(&object);
    }

    {
        ddwaf_object object;
        ddwaf_object_bool(&object, false);

        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_BOOL);

        // Getters
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_BOOL);
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
        EXPECT_EQ(ddwaf_object_get_bool(&object), false);

        ddwaf_object_free(&object);
    }
}

TEST(TestObjectIntegration, TestCreateArray)
{
    ddwaf_object container;
    ddwaf_object_array(&container);

    EXPECT_EQ(container.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(&container), 0);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&container), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_length(&container), 0);
    EXPECT_EQ(ddwaf_object_size(&container), 0);
    EXPECT_EQ(ddwaf_object_at_value(&container, 0), nullptr);

    ddwaf_object_free(&container);
}

TEST(TestObjectIntegration, TestCreateMap)
{
    ddwaf_object container;
    ddwaf_object_map(&container);

    EXPECT_EQ(container.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(&container), 0);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&container), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_length(&container), 0);
    EXPECT_EQ(ddwaf_object_size(&container), 0);
    EXPECT_EQ(ddwaf_object_at_value(&container, 0), nullptr);

    ddwaf_object_free(&container);
}

TEST(TestObjectIntegration, TestAddArray)
{
    ddwaf_object container;
    ddwaf_object_array(&container);

    ddwaf_object object;
    ddwaf_object_invalid(&object);

    EXPECT_FALSE(ddwaf_object_array_add(nullptr, &object));
    EXPECT_FALSE(ddwaf_object_array_add(&object, &container));

    EXPECT_TRUE(ddwaf_object_array_add(&container, &object));
    EXPECT_TRUE(ddwaf_object_array_add(&container, ddwaf_object_string_from_signed(&object, 42)));
    EXPECT_TRUE(ddwaf_object_array_add(&container, ddwaf_object_string_from_unsigned(&object, 43)));

    EXPECT_EQ(container.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(&container), 3);

    EXPECT_EQ(ddwaf_object_type(ddwaf_object_at_value(&container, 0)), DDWAF_OBJ_INVALID);

    EXPECT_TRUE((ddwaf_object_type(ddwaf_object_at_value(&container, 1)) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STREQ(ddwaf_object_get_string(ddwaf_object_at_value(&container, 1), nullptr), "42");

    EXPECT_TRUE((ddwaf_object_type(ddwaf_object_at_value(&container, 2)) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STREQ(ddwaf_object_get_string(ddwaf_object_at_value(&container, 2), nullptr), "43");

    // Getters
    EXPECT_EQ(ddwaf_object_type(&container), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_length(&container), 0);
    EXPECT_EQ(ddwaf_object_size(&container), 3);

    const auto *internal = ddwaf_object_at_value(&container, 0);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_INVALID);

    internal = ddwaf_object_at_value(&container, 1);
    EXPECT_TRUE((ddwaf_object_type(internal) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "42");

    internal = ddwaf_object_at_value(&container, 2);
    EXPECT_TRUE((ddwaf_object_type(internal) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "43");

    EXPECT_EQ(ddwaf_object_at_value(&container, 3), nullptr);

    ddwaf_object_free(&container);
}

TEST(TestObjectIntegration, TestAddMap)
{
    ddwaf_object map;
    ddwaf_object array;
    ddwaf_object tmp;

    ddwaf_object_map(&map);
    ddwaf_object_array(&array);

    EXPECT_FALSE(ddwaf_object_map_add(nullptr, "key", ddwaf_object_string_from_signed(&tmp, 42)));
    ddwaf_object_free(&tmp);
    EXPECT_FALSE(ddwaf_object_map_add(&array, "key", ddwaf_object_string_from_signed(&tmp, 42)));
    ddwaf_object_free(&tmp);
    EXPECT_FALSE(ddwaf_object_map_add(&map, nullptr, ddwaf_object_string_from_signed(&tmp, 42)));
    ddwaf_object_free(&tmp);

    EXPECT_FALSE(ddwaf_object_map_add(&map, "key", nullptr));

    EXPECT_TRUE(ddwaf_object_map_add(&map, "key", ddwaf_object_invalid(&tmp)));
    EXPECT_STREQ(ddwaf_object_get_string(&map.via.map.ptr[0].key, nullptr), "key");

    ASSERT_TRUE(ddwaf_object_map_add(&map, "key", ddwaf_object_string_from_signed(&tmp, 42)));
    EXPECT_STREQ(ddwaf_object_get_string(&map.via.map.ptr[1].key, nullptr), "key");

    ASSERT_TRUE(ddwaf_object_map_addl(&map, "key2", 4, ddwaf_object_string_from_signed(&tmp, 43)));
    EXPECT_STREQ(ddwaf_object_get_string(&map.via.map.ptr[2].key, nullptr), "key2");

    char *str = strdup("key3");
    ASSERT_TRUE(ddwaf_object_map_addl_nc(&map, str, 4, ddwaf_object_string_from_signed(&tmp, 44)));
    EXPECT_EQ(ddwaf_object_get_string(&map.via.map.ptr[3].key, nullptr), str);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&map), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_length(&map), 0);
    EXPECT_EQ(ddwaf_object_size(&map), 4);

    // size_t length;
    const auto *internal = ddwaf_object_at_value(&map, 0);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_INVALID);
    // EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key");

    internal = ddwaf_object_at_value(&map, 1);
    EXPECT_TRUE((ddwaf_object_type(internal) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "42");
    // EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key");
    // EXPECT_EQ(length, 3);

    internal = ddwaf_object_at_value(&map, 2);
    EXPECT_TRUE((ddwaf_object_type(internal) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "43");
    ////EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key2");
    // EXPECT_EQ(length, 4);

    internal = ddwaf_object_at_value(&map, 3);
    EXPECT_TRUE((ddwaf_object_type(internal) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "44");
    // EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key3");
    // EXPECT_EQ(length, 4);

    EXPECT_EQ(ddwaf_object_at_value(&map, 4), nullptr);

    ddwaf_object_free(&map);
    ddwaf_object_free(&array);
}

TEST(TestObjectIntegration, NullFree) { ddwaf_object_free(nullptr); }

TEST(TestObjectIntegration, FindNullObject)
{
    EXPECT_EQ(ddwaf_object_find(nullptr, STRL("key")), nullptr);
}

TEST(TestObjectIntegration, FindInvalidKey)
{
    ddwaf_object tmp;
    ddwaf_object map;
    ddwaf_object_map(&map);
    ddwaf_object_map_add(&map, "key", ddwaf_object_invalid(&tmp));

    EXPECT_EQ(ddwaf_object_find(&map, nullptr, 1), nullptr);
    EXPECT_EQ(ddwaf_object_find(&map, "", 0), nullptr);

    ddwaf_object_free(&map);
}

TEST(TestObjectIntegration, FindNotMap)
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_invalid(&tmp));

    EXPECT_EQ(ddwaf_object_find(&array, STRL("key")), nullptr);

    ddwaf_object_free(&array);
}

TEST(TestObjectIntegration, FindEmptyMap)
{
    ddwaf_object tmp;
    ddwaf_object map;
    ddwaf_object_map(&map);
    ddwaf_object_map_add(&map, "key", ddwaf_object_unsigned(&tmp, 42));

    const auto *object = ddwaf_object_find(&map, STRL("key"));
    ASSERT_NE(object, nullptr);
    EXPECT_EQ(ddwaf_object_type(object), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_unsigned(object), 42);

    ddwaf_object_free(&map);
}

} // namespace
