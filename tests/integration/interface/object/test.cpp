// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
#include "utils.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

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
    EXPECT_EQ(ddwaf_object_string(&object, nullptr), nullptr);
    EXPECT_EQ(ddwaf_object_stringl(&object, nullptr, 0), nullptr);
}

TEST(TestObject, TestString)
{

    ddwaf_object object;
    ddwaf_object_string(&object, "Sqreen");

    EXPECT_EQ(object.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(object.nbEntries, 6);
    EXPECT_EQ(object.parameterName, nullptr);
    EXPECT_STREQ((const char *)object.stringValue, "Sqreen");

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
    EXPECT_EQ(object.parameterName, nullptr);
    EXPECT_STREQ((const char *)object.stringValue, "Sqreen");

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
        ddwaf_object_string_from_signed(&object, INT64_MIN);

        EXPECT_EQ(object.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(object.nbEntries, 20);
        EXPECT_EQ(object.parameterName, nullptr);
        EXPECT_STREQ(object.stringValue, "-9223372036854775808");

        // Getters
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_STRING);
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

        EXPECT_EQ(object.type, DDWAF_OBJ_STRING);
        EXPECT_EQ(object.nbEntries, 19);
        EXPECT_EQ(object.parameterName, nullptr);
        EXPECT_STREQ(object.stringValue, "9223372036854775807");

        // Getters
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_STRING);
        EXPECT_EQ(ddwaf_object_length(&object), 19);
        EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "9223372036854775807");
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
        EXPECT_EQ(ddwaf_object_get_bool(&object), false);

        ddwaf_object_free(&object);
    }
}

TEST(TestObject, TestCreateIntForce)
{
    ddwaf_object object;
    ddwaf_object_signed(&object, INT64_MIN);

    EXPECT_EQ(object.type, DDWAF_OBJ_SIGNED);
    EXPECT_EQ(object.intValue, INT64_MIN);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_SIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), INT64_MIN);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
    EXPECT_EQ(ddwaf_object_get_bool(&object), false);

    ddwaf_object_free(&object);
}

TEST(TestObject, TestCreateUint)
{
    ddwaf_object object;
    ddwaf_object_string_from_unsigned(&object, UINT64_MAX);

    EXPECT_EQ(object.type, DDWAF_OBJ_STRING);
    EXPECT_EQ(object.nbEntries, 20);
    EXPECT_EQ(object.parameterName, nullptr);
    EXPECT_STREQ(object.stringValue, "18446744073709551615");

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_STRING);
    EXPECT_EQ(ddwaf_object_length(&object), 20);
    EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "18446744073709551615");
    EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
    EXPECT_EQ(ddwaf_object_get_bool(&object), false);

    ddwaf_object_free(&object);
}

TEST(TestObject, TestCreateUintForce)
{
    ddwaf_object object;
    ddwaf_object_unsigned(&object, UINT64_MAX);

    EXPECT_EQ(object.type, DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(object.uintValue, UINT64_MAX);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), UINT64_MAX);
    EXPECT_EQ(ddwaf_object_get_bool(&object), false);

    ddwaf_object_free(&object);
}

TEST(TestObject, TestCreateBool)
{
    {
        ddwaf_object object;
        ddwaf_object_bool(&object, true);

        EXPECT_EQ(object.type, DDWAF_OBJ_BOOL);
        EXPECT_EQ(object.boolean, true);

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

        EXPECT_EQ(object.type, DDWAF_OBJ_BOOL);
        EXPECT_EQ(object.boolean, false);

        // Getters
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_BOOL);
        EXPECT_EQ(ddwaf_object_get_signed(&object), 0);
        EXPECT_EQ(ddwaf_object_get_unsigned(&object), 0);
        EXPECT_EQ(ddwaf_object_get_bool(&object), false);

        ddwaf_object_free(&object);
    }
}

TEST(TestObject, TestCreateArray)
{
    ddwaf_object container;
    ddwaf_object_array(&container);

    EXPECT_EQ(container.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(container.nbEntries, 0);
    EXPECT_EQ(container.parameterName, nullptr);
    EXPECT_EQ(container.array, nullptr);

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
    EXPECT_EQ(container.parameterName, nullptr);
    EXPECT_EQ(container.array, nullptr);

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

    EXPECT_FALSE(ddwaf_object_array_add(nullptr, &object));
    EXPECT_FALSE(ddwaf_object_array_add(&object, &container));

    EXPECT_TRUE(ddwaf_object_array_add(&container, &object));
    EXPECT_TRUE(ddwaf_object_array_add(&container, ddwaf_object_string_from_signed(&object, 42)));
    EXPECT_TRUE(ddwaf_object_array_add(&container, ddwaf_object_string_from_unsigned(&object, 43)));

    EXPECT_EQ(container.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(container.nbEntries, 3);
    EXPECT_EQ(container.parameterName, nullptr);

    EXPECT_EQ(container.array[0].type, DDWAF_OBJ_INVALID);

    EXPECT_EQ(container.array[1].type, DDWAF_OBJ_STRING);
    EXPECT_STREQ(container.array[1].stringValue, "42");

    EXPECT_EQ(container.array[1].type, DDWAF_OBJ_STRING);
    EXPECT_STREQ(container.array[2].stringValue, "43");

    // Getters
    EXPECT_EQ(ddwaf_object_type(&container), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_length(&container), 0);
    EXPECT_EQ(ddwaf_object_size(&container), 3);

    const auto *internal = ddwaf_object_get_index(&container, 0);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_INVALID);

    internal = ddwaf_object_get_index(&container, 1);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "42");

    internal = ddwaf_object_get_index(&container, 2);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "43");

    EXPECT_EQ(ddwaf_object_get_index(&container, 3), nullptr);

    ddwaf_object_free(&container);
}

TEST(TestObject, TestAddMap)
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
    EXPECT_STREQ(map.array[0].parameterName, "key");

    ASSERT_TRUE(ddwaf_object_map_add(&map, "key", ddwaf_object_string_from_signed(&tmp, 42)));
    EXPECT_STREQ(map.array[1].parameterName, "key");

    ASSERT_TRUE(ddwaf_object_map_addl(&map, "key2", 4, ddwaf_object_string_from_signed(&tmp, 43)));
    EXPECT_STREQ(map.array[2].parameterName, "key2");

    char *str = strdup("key3");
    ASSERT_TRUE(ddwaf_object_map_addl_nc(&map, str, 4, ddwaf_object_string_from_signed(&tmp, 44)));
    EXPECT_EQ(map.array[3].parameterName, str);

    // Getters
    EXPECT_EQ(ddwaf_object_type(&map), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_length(&map), 0);
    EXPECT_EQ(ddwaf_object_size(&map), 4);

    size_t length;
    const auto *internal = ddwaf_object_get_index(&map, 0);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_INVALID);
    EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key");

    internal = ddwaf_object_get_index(&map, 1);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "42");
    EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key");
    EXPECT_EQ(length, 3);

    internal = ddwaf_object_get_index(&map, 2);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "43");
    EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key2");
    EXPECT_EQ(length, 4);

    internal = ddwaf_object_get_index(&map, 3);
    EXPECT_EQ(ddwaf_object_type(internal), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(internal, nullptr), "44");
    EXPECT_STREQ(ddwaf_object_get_key(internal, &length), "key3");
    EXPECT_EQ(length, 4);

    EXPECT_EQ(ddwaf_object_get_index(&map, 4), nullptr);

    ddwaf_object_free(&map);
    ddwaf_object_free(&array);
}

TEST(TestObject, NullFree) { ddwaf_object_free(nullptr); }

TEST(TestUTF8, TestLongUTF8)
{
    char buffer[DDWAF_MAX_STRING_LENGTH + 64] = {0};
    const uint8_t emoji[] = {0xe2, 0x98, 0xa2};

    // Only ASCII/single-byte characters
    memset(buffer, 'A', sizeof(buffer));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t)sizeof(buffer)), DDWAF_MAX_STRING_LENGTH);

    // New sequence starting just after the cut-off point
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH], emoji, sizeof(emoji));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t)sizeof(buffer)), DDWAF_MAX_STRING_LENGTH);
    memset(&buffer[DDWAF_MAX_STRING_LENGTH], 'A', sizeof(emoji));

    // We need to step back once
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH - 1], emoji, sizeof(emoji));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t)sizeof(buffer)), DDWAF_MAX_STRING_LENGTH - 1);
    memset(&buffer[DDWAF_MAX_STRING_LENGTH - 1], 'A', sizeof(emoji));

    // We need to step back twice
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH - 2], emoji, sizeof(emoji));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t)sizeof(buffer)), DDWAF_MAX_STRING_LENGTH - 2);
    memset(&buffer[DDWAF_MAX_STRING_LENGTH - 2], 'A', sizeof(emoji));

    // No need to step back, the sequence finishes just before the cutoff
    memcpy(&buffer[DDWAF_MAX_STRING_LENGTH - 3], emoji, sizeof(emoji));
    EXPECT_EQ(find_string_cutoff(buffer, (uint64_t)sizeof(buffer)), DDWAF_MAX_STRING_LENGTH);
}

TEST(TestObject, FindNullObject) { EXPECT_EQ(ddwaf_object_find(nullptr, STRL("key")), nullptr); }

TEST(TestObject, FindInvalidKey)
{
    ddwaf_object tmp;
    ddwaf_object map;
    ddwaf_object_map(&map);
    ddwaf_object_map_add(&map, "key", ddwaf_object_invalid(&tmp));

    EXPECT_EQ(ddwaf_object_find(&map, nullptr, 1), nullptr);
    EXPECT_EQ(ddwaf_object_find(&map, "", 0), nullptr);

    ddwaf_object_free(&map);
}

TEST(TestObject, FindNotMap)
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_invalid(&tmp));

    EXPECT_EQ(ddwaf_object_find(&array, STRL("key")), nullptr);

    ddwaf_object_free(&array);
}

TEST(TestObject, FindEmptyMap)
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

TEST(TestObject, FromJsonString)
{
    ddwaf_object object;
    const char *json = R"("hello world")";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "hello world");
    EXPECT_EQ(ddwaf_object_length(&object), 11);

    ddwaf_object_free(&object);
}

TEST(TestObject, FromJsonSignedInteger)
{
    ddwaf_object object;
    const char *json = "-123456789";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_SIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), -123456789);

    ddwaf_object_free(&object);
}

TEST(TestObject, FromJsonUnsignedInteger)
{
    ddwaf_object object;
    const char *json = "18446744073709551615"; // UINT64_MAX

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), UINT64_MAX);

    ddwaf_object_free(&object);
}

TEST(TestObject, FromJsonFloat)
{
    ddwaf_object object;
    const char *json = "3.14159";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_FLOAT);
    EXPECT_DOUBLE_EQ(ddwaf_object_get_float(&object), 3.14159);

    ddwaf_object_free(&object);
}

TEST(TestObject, FromJsonBoolean)
{
    {
        ddwaf_object object;
        const char *json = "true";

        EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_BOOL);
        EXPECT_TRUE(ddwaf_object_get_bool(&object));

        ddwaf_object_free(&object);
    }

    {
        ddwaf_object object;
        const char *json = "false";

        EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_BOOL);
        EXPECT_FALSE(ddwaf_object_get_bool(&object));

        ddwaf_object_free(&object);
    }
}

TEST(TestObject, FromJsonNull)
{
    ddwaf_object object;
    const char *json = "null";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_NULL);

    ddwaf_object_free(&object);
}

TEST(TestObject, FromJsonArray)
{
    ddwaf_object object;
    const char *json = R"([1, "hello", true, null])";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(&object), 4);

    // Check first element (number)
    const auto *elem0 = ddwaf_object_get_index(&object, 0);
    ASSERT_NE(elem0, nullptr);
    EXPECT_EQ(ddwaf_object_type(elem0), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_unsigned(elem0), 1);

    // Check second element (string)
    const auto *elem1 = ddwaf_object_get_index(&object, 1);
    ASSERT_NE(elem1, nullptr);
    EXPECT_EQ(ddwaf_object_type(elem1), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(elem1, nullptr), "hello");

    // Check third element (boolean)
    const auto *elem2 = ddwaf_object_get_index(&object, 2);
    ASSERT_NE(elem2, nullptr);
    EXPECT_EQ(ddwaf_object_type(elem2), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(elem2));

    // Check fourth element (null)
    const auto *elem3 = ddwaf_object_get_index(&object, 3);
    ASSERT_NE(elem3, nullptr);
    EXPECT_EQ(ddwaf_object_type(elem3), DDWAF_OBJ_NULL);

    ddwaf_object_free(&object);
}

TEST(TestObject, FromJsonObject)
{
    ddwaf_object object;
    const char *json = R"({"name": "John", "age": 30, "active": true})";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(&object), 3);

    // Check name field
    const auto *name_obj = ddwaf_object_find(&object, STRL("name"));
    ASSERT_NE(name_obj, nullptr);
    EXPECT_EQ(ddwaf_object_type(name_obj), DDWAF_OBJ_STRING);
    EXPECT_STREQ(ddwaf_object_get_string(name_obj, nullptr), "John");

    // Check age field
    const auto *age_obj = ddwaf_object_find(&object, STRL("age"));
    ASSERT_NE(age_obj, nullptr);
    EXPECT_EQ(ddwaf_object_type(age_obj), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_unsigned(age_obj), 30);

    // Check active field
    const auto *active_obj = ddwaf_object_find(&object, STRL("active"));
    ASSERT_NE(active_obj, nullptr);
    EXPECT_EQ(ddwaf_object_type(active_obj), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(active_obj));

    ddwaf_object_free(&object);
}

TEST(TestObject, FromJsonNestedStructure)
{
    ddwaf_object object;
    const char *json = R"({
        "user": {
            "name": "Alice",
            "preferences": {
                "theme": "dark",
                "notifications": true
            }
        },
        "scores": [95, 87, 92],
        "metadata": null
    })";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
    EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_MAP);

    // Check user object
    const auto *user_obj = ddwaf_object_find(&object, STRL("user"));
    ASSERT_NE(user_obj, nullptr);
    EXPECT_EQ(ddwaf_object_type(user_obj), DDWAF_OBJ_MAP);

    // Check nested name
    const auto *name_obj = ddwaf_object_find(user_obj, STRL("name"));
    ASSERT_NE(name_obj, nullptr);
    EXPECT_STREQ(ddwaf_object_get_string(name_obj, nullptr), "Alice");

    // Check preferences object
    const auto *prefs_obj = ddwaf_object_find(user_obj, STRL("preferences"));
    ASSERT_NE(prefs_obj, nullptr);
    EXPECT_EQ(ddwaf_object_type(prefs_obj), DDWAF_OBJ_MAP);

    // Check theme in preferences
    const auto *theme_obj = ddwaf_object_find(prefs_obj, STRL("theme"));
    ASSERT_NE(theme_obj, nullptr);
    EXPECT_STREQ(ddwaf_object_get_string(theme_obj, nullptr), "dark");

    // Check scores array
    const auto *scores_obj = ddwaf_object_find(&object, STRL("scores"));
    ASSERT_NE(scores_obj, nullptr);
    EXPECT_EQ(ddwaf_object_type(scores_obj), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(scores_obj), 3);

    // Check first score
    const auto *score0 = ddwaf_object_get_index(scores_obj, 0);
    ASSERT_NE(score0, nullptr);
    EXPECT_EQ(ddwaf_object_get_unsigned(score0), 95);

    // Check metadata (null)
    const auto *metadata_obj = ddwaf_object_find(&object, STRL("metadata"));
    ASSERT_NE(metadata_obj, nullptr);
    EXPECT_EQ(ddwaf_object_type(metadata_obj), DDWAF_OBJ_NULL);

    ddwaf_object_free(&object);
}

TEST(TestObject, FromJsonInvalidCases)
{
    ddwaf_object object;

    // Test null parameters
    EXPECT_FALSE(ddwaf_object_from_json(nullptr, "{}", 2));
    EXPECT_FALSE(ddwaf_object_from_json(&object, nullptr, 2));

    // Test zero length
    EXPECT_FALSE(ddwaf_object_from_json(&object, "{}", 0));

    // Test empty string (should fail)
    const char *empty_json = "";
    EXPECT_FALSE(ddwaf_object_from_json(&object, empty_json, strlen(empty_json)));
}

TEST(TestObject, FromJsonEmptyContainers)
{
    {
        // Empty array
        ddwaf_object object;
        const char *json = "[]";

        EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_size(&object), 0);

        ddwaf_object_free(&object);
    }

    {
        // Empty object
        ddwaf_object object;
        const char *json = "{}";

        EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json)));
        EXPECT_EQ(ddwaf_object_type(&object), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_size(&object), 0);

        ddwaf_object_free(&object);
    }
}

} // namespace
