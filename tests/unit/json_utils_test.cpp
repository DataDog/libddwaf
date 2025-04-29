// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "json_utils.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestJsonUtils, Empty)
{
    auto object = ddwaf::json_to_object("");
    EXPECT_EQ(object.type, DDWAF_OBJ_INVALID);
}

TEST(TestJsonUtils, Null)
{
    auto object = ddwaf::json_to_object("null");
    EXPECT_EQ(object.type, DDWAF_OBJ_NULL);
}

TEST(TestJsonUtils, Boolean)
{
    {
        auto object = ddwaf::json_to_object("true");
        EXPECT_EQ(object.type, DDWAF_OBJ_BOOL);
        EXPECT_EQ(object.boolean, true);
    }

    {
        auto object = ddwaf::json_to_object("false");
        EXPECT_EQ(object.type, DDWAF_OBJ_BOOL);
        EXPECT_EQ(object.boolean, false);
    }
}

TEST(TestJsonUtils, Signed)
{
    auto object = ddwaf::json_to_object("-5");
    EXPECT_EQ(object.type, DDWAF_OBJ_SIGNED);
    EXPECT_EQ(object.intValue, -5);
}

TEST(TestJsonUtils, Unsigned)
{
    auto object = ddwaf::json_to_object("18446744073709551615");
    EXPECT_EQ(object.type, DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(object.intValue, 18446744073709551615ULL);
}

TEST(TestJsonUtils, Double)
{
    auto object = ddwaf::json_to_object("5.5");
    EXPECT_EQ(object.type, DDWAF_OBJ_FLOAT);
    EXPECT_EQ(object.f64, 5.5);
}

TEST(TestJsonUtils, String)
{
    auto object = ddwaf::json_to_object("\"this is a string\"");
    EXPECT_EQ(object.type, DDWAF_OBJ_STRING);

    std::string_view value{object.stringValue, static_cast<std::size_t>(object.nbEntries)};
    EXPECT_STRV(value, "this is a string");
    ddwaf_object_free(&object);
}

TEST(TestJsonUtils, EmptyArray)
{
    auto object = ddwaf::json_to_object("[]");
    EXPECT_EQ(object.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(object.nbEntries, 0);
    ddwaf_object_free(&object);
}

TEST(TestJsonUtils, ArrayOfScalars)
{
    auto object = ddwaf::json_to_object("[null, true, -1, 18446744073709551615, 1.2, \"string\"]");
    EXPECT_EQ(object.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(object.nbEntries, 6);

    EXPECT_EQ(object.array[0].type, DDWAF_OBJ_NULL);

    EXPECT_EQ(object.array[1].type, DDWAF_OBJ_BOOL);
    EXPECT_EQ(object.array[1].boolean, true);

    EXPECT_EQ(object.array[2].type, DDWAF_OBJ_SIGNED);
    EXPECT_EQ(object.array[2].intValue, -1);

    EXPECT_EQ(object.array[3].type, DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(object.array[3].uintValue, 18446744073709551615ULL);

    EXPECT_EQ(object.array[4].type, DDWAF_OBJ_FLOAT);
    EXPECT_EQ(object.array[4].f64, 1.2);

    EXPECT_EQ(object.array[5].type, DDWAF_OBJ_STRING);
    std::string_view value{
        object.array[5].stringValue, static_cast<std::size_t>(object.array[5].nbEntries)};
    EXPECT_STRV(value, "string");

    ddwaf_object_free(&object);
}

TEST(TestJsonUtils, NestedArray)
{
    std::string json_str =
        R"([null,true,-1,18446744073709551615,1.2,"string",["array",["array"],{"map":true}],{"map":{"map":-42},"array":["array",{"map":1729}]}])";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object, json_str);

    ddwaf_object_free(&object);
}

TEST(TestJsonUtils, NestedEmptyArraysHardcodedLimit)
{
    std::string json_str = R"([[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]])";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object, R"([[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]])");

    ddwaf_object_free(&object);
}

TEST(TestJsonUtils, EmptyMap)
{
    auto object = ddwaf::json_to_object("{}");
    EXPECT_EQ(object.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(object.nbEntries, 0);
    ddwaf_object_free(&object);
}

TEST(TestJsonUtils, MapOfScalars)
{
    auto object = ddwaf::json_to_object(
        R"({"null":null,"bool":true,"int":-1,"uint":18446744073709551615,"double":1.2,"string":"string"})");
    EXPECT_EQ(object.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(object.nbEntries, 6);

    {
        auto &child = object.array[0];
        EXPECT_EQ(child.type, DDWAF_OBJ_NULL);

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};
        EXPECT_STRV(key, "null");
    }

    {
        auto &child = object.array[1];
        EXPECT_EQ(child.type, DDWAF_OBJ_BOOL);
        EXPECT_EQ(child.boolean, true);

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};
        EXPECT_STRV(key, "bool");
    }

    {
        auto &child = object.array[2];
        EXPECT_EQ(child.type, DDWAF_OBJ_SIGNED);
        EXPECT_EQ(child.intValue, -1);

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};
        EXPECT_STRV(key, "int");
    }

    {
        auto &child = object.array[3];
        EXPECT_EQ(child.type, DDWAF_OBJ_UNSIGNED);
        EXPECT_EQ(child.uintValue, 18446744073709551615ULL);

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};
        EXPECT_STRV(key, "uint");
    }

    {
        auto &child = object.array[4];
        EXPECT_EQ(child.type, DDWAF_OBJ_FLOAT);
        EXPECT_EQ(child.f64, 1.2);

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};
        EXPECT_STRV(key, "double");
    }

    {
        auto &child = object.array[5];
        EXPECT_EQ(child.type, DDWAF_OBJ_STRING);
        std::string_view value{child.stringValue, static_cast<std::size_t>(child.nbEntries)};
        EXPECT_STRV(value, "string");

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};
        EXPECT_STRV(key, "string");
    }

    ddwaf_object_free(&object);
}

TEST(TestJsonUtils, NestedMap)
{
    std::string json_str =
        R"({"null":null,"bool":true,"int":-1,"uint":18446744073709551615,"double":1.2,"string":"string","array":["array",["array"],{"map":true}],"map":{"map":{"map":-42},"array":["array",{"map":1729}]}})";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object, json_str);

    ddwaf_object_free(&object);
}

TEST(TestJsonUtils, NestedEmptyMapsHardcodedLimit)
{
    std::string json_str =
        R"({"0":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"15":{"16":{"17":{"18":{"19":{"20":{}}}}}}}}}}}}}}}}}}}}}})";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object,
        R"({"0":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"15":{"16":{"17":{"18":{"19":{}}}}}}}}}}}}}}}}}}}}})");

    ddwaf_object_free(&object);
}

} // namespace
