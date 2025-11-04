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
    EXPECT_TRUE(ddwaf_object_is_invalid(&object));
}

TEST(TestObjectIntegration, TestInvalidString)
{
    ddwaf_object object;
    EXPECT_EQ(ddwaf_object_set_string_nocopy(&object, nullptr, 0), nullptr);
    EXPECT_EQ(ddwaf_object_set_string_literal(&object, nullptr, 0), nullptr);
}

TEST(TestObjectIntegration, TestEmptyString)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_object object;
    EXPECT_EQ(ddwaf_object_set_string(&object, nullptr, 0, alloc), &object);
}

TEST(TestObjectIntegration, TestString)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;
    ddwaf_object_set_string(&object, STRL("Sqreen"), alloc);

    EXPECT_TRUE((ddwaf_object_get_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_EQ(ddwaf_object_get_length(&object), 6);
    EXPECT_STRV(object_to_view(object), "Sqreen");
    EXPECT_TRUE(ddwaf_object_is_string(&object));

    // Getters
    EXPECT_TRUE((ddwaf_object_get_type(&object) & DDWAF_OBJ_STRING) != 0);
    EXPECT_STRV(object_to_view(object), "Sqreen");
    EXPECT_EQ(ddwaf_object_get_length(&object), 6);
    EXPECT_EQ(ddwaf_object_get_size(&object), 0);
    EXPECT_TRUE(ddwaf_object_is_string(&object));

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

    EXPECT_TRUE(ddwaf_object_is_signed(&object));
    EXPECT_FALSE(ddwaf_object_is_unsigned(&object));
    EXPECT_FALSE(ddwaf_object_is_float(&object));

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

    EXPECT_TRUE(ddwaf_object_is_unsigned(&object));
    EXPECT_FALSE(ddwaf_object_is_signed(&object));
    EXPECT_FALSE(ddwaf_object_is_float(&object));

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
        EXPECT_TRUE(ddwaf_object_is_bool(&object));

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
        EXPECT_TRUE(ddwaf_object_is_bool(&object));

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
    EXPECT_TRUE(ddwaf_object_is_array(&container));

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
    EXPECT_TRUE(ddwaf_object_is_map(&container));

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

TEST(TestObject, FromJsonString)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;
    const char *json = R"("hello world")";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
    EXPECT_TRUE(ddwaf_object_is_string(&object));
    EXPECT_STREQ(ddwaf_object_get_string(&object, nullptr), "hello world");
    EXPECT_EQ(ddwaf_object_get_length(&object), 11);

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObject, FromJsonSignedInteger)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;
    const char *json = "-123456789";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_SIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&object), -123456789);
    EXPECT_TRUE(ddwaf_object_is_signed(&object));
    EXPECT_FALSE(ddwaf_object_is_unsigned(&object));
    EXPECT_FALSE(ddwaf_object_is_float(&object));

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObject, FromJsonUnsignedInteger)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;
    const char *json = "18446744073709551615"; // UINT64_MAX

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_unsigned(&object), UINT64_MAX);
    EXPECT_TRUE(ddwaf_object_is_unsigned(&object));
    EXPECT_FALSE(ddwaf_object_is_signed(&object));
    EXPECT_FALSE(ddwaf_object_is_float(&object));

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObject, FromJsonFloat)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;
    const char *json = "3.14159";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_FLOAT);
    EXPECT_DOUBLE_EQ(ddwaf_object_get_float(&object), 3.14159);
    EXPECT_TRUE(ddwaf_object_is_float(&object));
    EXPECT_FALSE(ddwaf_object_is_unsigned(&object));
    EXPECT_FALSE(ddwaf_object_is_signed(&object));

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObject, FromJsonBoolean)
{
    auto *alloc = ddwaf_get_default_allocator();

    {
        ddwaf_object object;
        const char *json = "true";

        EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
        EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_BOOL);
        EXPECT_TRUE(ddwaf_object_get_bool(&object));
        EXPECT_TRUE(ddwaf_object_is_bool(&object));

        ddwaf_object_destroy(&object, alloc);
    }

    {
        ddwaf_object object;
        const char *json = "false";

        EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
        EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_BOOL);
        EXPECT_FALSE(ddwaf_object_get_bool(&object));
        EXPECT_TRUE(ddwaf_object_is_bool(&object));

        ddwaf_object_destroy(&object, alloc);
    }
}

TEST(TestObject, FromJsonNull)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;
    const char *json = "null";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_NULL);
    EXPECT_TRUE(ddwaf_object_is_null(&object));

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObject, FromJsonArray)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;
    const char *json = R"([1, "hello", true, null])";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(&object), 4);

    // Check first element (number)
    const auto *elem0 = ddwaf_object_at_value(&object, 0);
    ASSERT_NE(elem0, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(elem0), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_unsigned(elem0), 1);

    // Check second element (string)
    const auto *elem1 = ddwaf_object_at_value(&object, 1);
    ASSERT_NE(elem1, nullptr);
    EXPECT_TRUE(ddwaf_object_is_string(elem1));
    EXPECT_STREQ(ddwaf_object_get_string(elem1, nullptr), "hello");

    // Check third element (boolean)
    const auto *elem2 = ddwaf_object_at_value(&object, 2);
    ASSERT_NE(elem2, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(elem2), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(elem2));

    // Check fourth element (null)
    const auto *elem3 = ddwaf_object_at_value(&object, 3);
    ASSERT_NE(elem3, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(elem3), DDWAF_OBJ_NULL);

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObject, FromJsonObject)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;
    const char *json = R"({"name": "John", "age": 30, "active": true})";

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(&object), 3);

    // Check name field
    const auto *name_obj = ddwaf_object_find(&object, STRL("name"));
    ASSERT_NE(name_obj, nullptr);
    EXPECT_TRUE(ddwaf_object_is_string(name_obj));
    EXPECT_STREQ(ddwaf_object_get_string(name_obj, nullptr), "John");

    // Check age field
    const auto *age_obj = ddwaf_object_find(&object, STRL("age"));
    ASSERT_NE(age_obj, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(age_obj), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_unsigned(age_obj), 30);

    // Check active field
    const auto *active_obj = ddwaf_object_find(&object, STRL("active"));
    ASSERT_NE(active_obj, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(active_obj), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(active_obj));

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObject, FromJsonNestedStructure)
{
    auto *alloc = ddwaf_get_default_allocator();

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

    EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
    EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_MAP);

    // Check user object
    const auto *user_obj = ddwaf_object_find(&object, STRL("user"));
    ASSERT_NE(user_obj, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(user_obj), DDWAF_OBJ_MAP);

    // Check nested name
    const auto *name_obj = ddwaf_object_find(user_obj, STRL("name"));
    ASSERT_NE(name_obj, nullptr);
    EXPECT_STREQ(ddwaf_object_get_string(name_obj, nullptr), "Alice");

    // Check preferences object
    const auto *prefs_obj = ddwaf_object_find(user_obj, STRL("preferences"));
    ASSERT_NE(prefs_obj, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(prefs_obj), DDWAF_OBJ_MAP);

    // Check theme in preferences
    const auto *theme_obj = ddwaf_object_find(prefs_obj, STRL("theme"));
    ASSERT_NE(theme_obj, nullptr);
    EXPECT_STREQ(ddwaf_object_get_string(theme_obj, nullptr), "dark");

    // Check scores array
    const auto *scores_obj = ddwaf_object_find(&object, STRL("scores"));
    ASSERT_NE(scores_obj, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(scores_obj), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(scores_obj), 3);

    // Check first score
    const auto *score0 = ddwaf_object_at_value(scores_obj, 0);
    ASSERT_NE(score0, nullptr);
    EXPECT_EQ(ddwaf_object_get_unsigned(score0), 95);

    // Check metadata (null)
    const auto *metadata_obj = ddwaf_object_find(&object, STRL("metadata"));
    ASSERT_NE(metadata_obj, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(metadata_obj), DDWAF_OBJ_NULL);

    ddwaf_object_destroy(&object, alloc);
}

TEST(TestObject, FromJsonInvalidCases)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object object;

    // Test null parameters
    EXPECT_FALSE(ddwaf_object_from_json(nullptr, "{}", 2, alloc));
    EXPECT_FALSE(ddwaf_object_from_json(&object, nullptr, 2, alloc));

    // Test zero length
    EXPECT_FALSE(ddwaf_object_from_json(&object, "{}", 0, alloc));

    // Test empty string (should fail)
    const char *empty_json = "";
    EXPECT_FALSE(ddwaf_object_from_json(&object, empty_json, strlen(empty_json), alloc));

    // Test invalid JSON syntax
    const char *invalid_json1 = R"({"invalid": json,})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json1, strlen(invalid_json1), alloc));

    // Test malformed JSON - unclosed string
    const char *malformed_json1 = R"({"unclosed": "string)";
    EXPECT_FALSE(ddwaf_object_from_json(&object, malformed_json1, strlen(malformed_json1), alloc));

    // Test malformed JSON - unclosed object
    const char *malformed_json2 = R"({"key": "value")";
    EXPECT_FALSE(ddwaf_object_from_json(&object, malformed_json2, strlen(malformed_json2), alloc));

    // Test malformed JSON - unclosed array
    const char *malformed_json3 = R"([1, 2, 3)";
    EXPECT_FALSE(ddwaf_object_from_json(&object, malformed_json3, strlen(malformed_json3), alloc));

    // Test invalid JSON - missing quotes around key
    const char *invalid_json2 = R"({key: "value"})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json2, strlen(invalid_json2), alloc));

    // Test invalid JSON - trailing comma in object
    const char *invalid_json3 = R"({"key": "value",})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json3, strlen(invalid_json3), alloc));

    // Test invalid JSON - trailing comma in array
    const char *invalid_json4 = R"([1, 2, 3,])";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json4, strlen(invalid_json4), alloc));

    // Test invalid JSON - single quotes instead of double quotes
    const char *invalid_json5 = R"({'key': 'value'})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json5, strlen(invalid_json5), alloc));

    // Test invalid JSON - undefined value
    const char *invalid_json6 = R"({"key": undefined})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json6, strlen(invalid_json6), alloc));

    // Test invalid JSON - comment (not allowed in JSON)
    const char *invalid_json7 = R"({"key": "value" /* comment */})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json7, strlen(invalid_json7), alloc));

    // Test invalid JSON - multiple values at root level
    const char *invalid_json8 = R"({"key1": "value1"} {"key2": "value2"})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json8, strlen(invalid_json8), alloc));

    // Test invalid JSON - missing value
    const char *invalid_json9 = R"({"key":})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json9, strlen(invalid_json9), alloc));

    // Test invalid JSON - missing colon
    const char *invalid_json10 = R"({"key" "value"})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json10, strlen(invalid_json10), alloc));

    // Test invalid JSON - invalid escape sequence
    const char *invalid_json11 = R"({"key": "invalid\escape"})";
    EXPECT_FALSE(ddwaf_object_from_json(&object, invalid_json11, strlen(invalid_json11), alloc));

    // Test truncated JSON
    const char *truncated_json = R"({"key": "val)";
    EXPECT_FALSE(ddwaf_object_from_json(&object, truncated_json, strlen(truncated_json), alloc));
}

TEST(TestObject, FromJsonEmptyContainers)
{
    auto *alloc = ddwaf_get_default_allocator();

    {
        // Empty array
        ddwaf_object object;
        const char *json = "[]";

        EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
        EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(&object), 0);

        ddwaf_object_destroy(&object, alloc);
    }

    {
        // Empty object
        ddwaf_object object;
        const char *json = "{}";

        EXPECT_TRUE(ddwaf_object_from_json(&object, json, strlen(json), alloc));
        EXPECT_EQ(ddwaf_object_get_type(&object), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(&object), 0);

        ddwaf_object_destroy(&object, alloc);
    }
}

} // namespace
