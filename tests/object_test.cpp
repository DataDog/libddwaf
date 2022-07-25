// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestObject, TestCreateInvalid)
{
    ddwaf_object object;
    ddwaf_object_invalid(&object);
    EXPECT_EQ(object.type, DDWAF_OBJ_INVALID);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_INVALID);
}

TEST(TestObject, TestInvalidString)
{
    ddwaf_object object;
    EXPECT_EQ(ddwaf_object_string(&object, NULL), nullptr);
    EXPECT_EQ(ddwaf_object_stringl(&object, NULL, 0), nullptr);
}

TEST(TestObject, TestString)
{

    ddwaf_object object;
    ddwaf_object_string(&object, "Sqreen");

    EXPECT_EQ(object.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(object.nbEntries, 6);
    EXPECT_TRUE(object.parameterName == NULL);
    EXPECT_STREQ((const char*) object.stringValue, "Sqreen");

    // Getters
    size_t length;
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(&object, &length), "Sqreen");
    EXPECT_EQ(length, 6);
    EXPECT_EQ(ddwaf_object_length(&object), 6);
    EXPECT_EQ(ddwaf_object_size(&object), 0);

    ddwaf_object_free(&object);
}

TEST(TestObject, TestCreateStringl)
{
    ddwaf_object object;
    ddwaf_object_stringl(&object, "Sqreen", sizeof("Sqreen") - 1);

    EXPECT_EQ(object.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(object.nbEntries, 6);
    EXPECT_TRUE(object.parameterName == NULL);
    EXPECT_STREQ((const char*) object.stringValue, "Sqreen");

    // Getters
    size_t length;
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(&object, &length), "Sqreen");
    EXPECT_EQ(length, 6);
    EXPECT_EQ(ddwaf_object_length(&object), 6);
    EXPECT_EQ(ddwaf_object_size(&object), 0);

    ddwaf_object_free(&object);
}

TEST(TestObject, TestCreateInt)
{
    {
        ddwaf_object object;
        ddwaf_object_signed(&object, INT64_MIN);

        EXPECT_EQ(object.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(object.nbEntries, 20);
        EXPECT_TRUE(object.parameterName == NULL);
        EXPECT_STREQ(object.stringValue, "-9223372036854775808");

        // Getters
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_STRING);
        EXPECT_EQ(ddwaf_object_length(&object), 20);
        EXPECT_STREQ(ddwaf_object_get_string(&object, NULL), "-9223372036854775808");
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);

        ddwaf_object_free(&object);
    }

    {
        ddwaf_object object;
        ddwaf_object_signed(&object, INT64_MAX);

        EXPECT_EQ(object.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(object.nbEntries, 19);
        EXPECT_TRUE(object.parameterName == NULL);
        EXPECT_STREQ(object.stringValue, "9223372036854775807");

        // Getters
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_STRING);
        EXPECT_EQ(ddwaf_object_length(&object), 19);
        EXPECT_STREQ(ddwaf_object_get_string(&object, NULL), "9223372036854775807");
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);

        ddwaf_object_free(&object);
    }
}

TEST(TestObject, TestCreateIntForce)
{
    ddwaf_object object;
    ddwaf_object_signed_force(&object, INT64_MIN);

    EXPECT_EQ(object.type, DDWAF_OBJ_SIGNED);
    EXPECT_EQ(object.intValue, INT64_MIN);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_SIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), INT64_MIN);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);

    ddwaf_object_free(&object);
}

TEST(TestObject, TestCreateUint)
{
    ddwaf_object object;
    ddwaf_object_unsigned(&object, UINT64_MAX);

    EXPECT_EQ(object.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(object.nbEntries, 20);
    EXPECT_TRUE(object.parameterName == NULL);
    EXPECT_STREQ(object.stringValue, "18446744073709551615");

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_STRING);
    EXPECT_EQ(ddwaf_object_length(&object), 20);
    EXPECT_STREQ(ddwaf_object_get_string(&object, NULL), "18446744073709551615");
    EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);

    ddwaf_object_free(&object);
}

TEST(TestObject, TestCreateUintForce)
{
    ddwaf_object object;
    ddwaf_object_unsigned_force(&object, UINT64_MAX);

    EXPECT_EQ(object.type, DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(object.uintValue, UINT64_MAX);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), UINT64_MAX);

    ddwaf_object_free(&object);
}

TEST(TestObject, TestCreateArray)
{
    ddwaf_object container;
    ddwaf_object_array(&container);

    EXPECT_EQ(container.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(container.nbEntries, 0);
    EXPECT_TRUE(container.parameterName == NULL);
    EXPECT_TRUE(container.array == NULL);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&container), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_length(&container), 0);
    EXPECT_EQ(ddwaf_object_size(&container), 0);
    EXPECT_EQ(ddwaf_object_get_index(&container, 0), nullptr);

    ddwaf_object_free(&container);
}

TEST(TestObject, TestCreateMap)
{
    ddwaf_object container;
    ddwaf_object_map(&container);

    EXPECT_EQ(container.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(container.nbEntries, 0);
    EXPECT_TRUE(container.parameterName == NULL);
    EXPECT_TRUE(container.array == NULL);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&container), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_length(&container), 0);
    EXPECT_EQ(ddwaf_object_size(&container), 0);
    EXPECT_EQ(ddwaf_object_get_index(&container, 0), nullptr);

    ddwaf_object_free(&container);
}

TEST(TestObject, TestAddArray)
{
    ddwaf_object container;
    ddwaf_object_array(&container);

    ddwaf_object object;
    ddwaf_object_invalid(&object);

    EXPECT_FALSE(ddwaf_object_array_add(NULL, &object));
    EXPECT_FALSE(ddwaf_object_array_add(&object, &container));
    EXPECT_FALSE(ddwaf_object_array_add(&container, &object));

    EXPECT_TRUE(ddwaf_object_array_add(&container, ddwaf_object_signed(&object, 42)));
    EXPECT_TRUE(ddwaf_object_array_add(&container, ddwaf_object_unsigned(&object, 43)));

    EXPECT_EQ(container.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(container.nbEntries, 2);
    EXPECT_TRUE(container.parameterName == NULL);

    EXPECT_EQ(container.array[0].type, DDWAF_OBJ_STRING);
    EXPECT_STREQ(container.array[0].stringValue, "42");

    EXPECT_EQ(container.array[1].type, DDWAF_OBJ_STRING);
    EXPECT_STREQ(container.array[1].stringValue, "43");

    // Getters
    EXPECT_EQ(ddwaf_object_type(&container), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_length(&container), 0);
    EXPECT_EQ(ddwaf_object_size(&container), 2);

    ddwaf_object* internal;
    internal = ddwaf_object_get_index(&container, 0);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "42");

    internal = ddwaf_object_get_index(&container, 1);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "43");

    EXPECT_EQ(ddwaf_object_get_index(&container, 2), nullptr);

    ddwaf_object_free(&container);
}

TEST(TestObject, TestAddMap)
{
    ddwaf_object map, array, tmp;

    ddwaf_object_map(&map);
    ddwaf_object_array(&array);

    EXPECT_FALSE(ddwaf_object_map_add(NULL, "key", ddwaf_object_signed(&tmp, 42)));
    ddwaf_object_free(&tmp);
    EXPECT_FALSE(ddwaf_object_map_add(&array, "key", ddwaf_object_signed(&tmp, 42)));
    ddwaf_object_free(&tmp);
    EXPECT_FALSE(ddwaf_object_map_add(&map, NULL, ddwaf_object_signed(&tmp, 42)));
    ddwaf_object_free(&tmp);

    EXPECT_FALSE(ddwaf_object_map_add(&map, "key", ddwaf_object_invalid(&tmp)));
    EXPECT_FALSE(ddwaf_object_map_add(&map, "key", NULL));

    ASSERT_TRUE(ddwaf_object_map_add(&map, "key", ddwaf_object_signed(&tmp, 42)));
    EXPECT_STREQ(map.array[0].parameterName, "key");

    ASSERT_TRUE(ddwaf_object_map_addl(&map, "key2", 4, ddwaf_object_signed(&tmp, 43)));
    EXPECT_STREQ(map.array[1].parameterName, "key2");

    char* str = strdup("key3");
    ASSERT_TRUE(ddwaf_object_map_addl_nc(&map, str, 4, ddwaf_object_signed(&tmp, 44)));
    EXPECT_EQ(map.array[2].parameterName, str);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&map), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_length(&map), 0);
    EXPECT_EQ(ddwaf_object_size(&map), 3);

    size_t length;
    ddwaf_object* internal;
    internal = ddwaf_object_get_index(&map, 0);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "42");
    EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key");
    EXPECT_EQ(length, 3);

    internal = ddwaf_object_get_index(&map, 1);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "43");
    EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key2");
    EXPECT_EQ(length, 4);

    internal = ddwaf_object_get_index(&map, 2);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "44");
    EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key3");
    EXPECT_EQ(length, 4);

    EXPECT_EQ(ddwaf_object_get_index(&map, 3), nullptr);

    ddwaf_object_free(&map);
    ddwaf_object_free(&array);
}

TEST(TestObject, TestFree)
{
    ddwaf_object_free(NULL);
}

TEST(TestUTF8, TestLongUTF8)
{
    char buffer[DDWAF_MAX_STRING_LENGTH + 64] = { 0 };
    const uint8_t emoji[]                     = { 0xe2, 0x98, 0xa2 };

    //Only ASCII/single-byte characters
    memset(buffer, 'A', sizeof(buffer));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t) sizeof(buffer)), DDWAF_MAX_STRING_LENGTH);

    //New sequence starting just after the cut-off point
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH], emoji, sizeof(emoji));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t) sizeof(buffer)), DDWAF_MAX_STRING_LENGTH);
    memset(&buffer[DDWAF_MAX_STRING_LENGTH], 'A', sizeof(emoji));

    //We need to step back once
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH - 1], emoji, sizeof(emoji));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t) sizeof(buffer)), DDWAF_MAX_STRING_LENGTH - 1);
    memset(&buffer[DDWAF_MAX_STRING_LENGTH - 1], 'A', sizeof(emoji));

    //We need to step back twice
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH - 2], emoji, sizeof(emoji));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t) sizeof(buffer)), DDWAF_MAX_STRING_LENGTH - 2);
    memset(&buffer[DDWAF_MAX_STRING_LENGTH - 2], 'A', sizeof(emoji));

    //No need to step back, the sequence finishes just before the cutoff
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH - 3], emoji, sizeof(emoji));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t) sizeof(buffer)), DDWAF_MAX_STRING_LENGTH);
}
