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
    EXPECT_EQ(object.type(), object_type::invalid);
}

TEST(TestJsonUtils, Null)
{
    auto object = ddwaf::json_to_object("null");
    EXPECT_EQ(object.type(), object_type::null);
}

TEST(TestJsonUtils, Boolean)
{
    {
        auto object = ddwaf::json_to_object("true");
        EXPECT_EQ(object.type(), object_type::boolean);
        EXPECT_EQ(object.as<bool>(), true);
    }

    {
        auto object = ddwaf::json_to_object("false");
        EXPECT_EQ(object.type(), object_type::boolean);
        EXPECT_EQ(object.as<bool>(), false);
    }
}

TEST(TestJsonUtils, Signed)
{
    auto object = ddwaf::json_to_object("-5");
    EXPECT_EQ(object.type(), object_type::int64);
    EXPECT_EQ(object.as<int64_t>(), -5);
}

TEST(TestJsonUtils, Unsigned)
{
    auto object = ddwaf::json_to_object("18446744073709551615");
    EXPECT_EQ(object.type(), object_type::uint64);
    EXPECT_EQ(object.as<uint64_t>(), 18446744073709551615ULL);
}

TEST(TestJsonUtils, Double)
{
    auto object = ddwaf::json_to_object("5.5");
    EXPECT_EQ(object.type(), object_type::float64);
    EXPECT_EQ(object.as<double>(), 5.5);
}

TEST(TestJsonUtils, String)
{
    auto object = ddwaf::json_to_object("\"this is a string\"");
    EXPECT_EQ(object.type(), object_type::string);

    EXPECT_STRV(object.as<std::string_view>(), "this is a string");
}

TEST(TestJsonUtils, EmptyArray)
{
    auto object = ddwaf::json_to_object("[]");
    EXPECT_EQ(object.type(), object_type::array);
    EXPECT_EQ(object.size(), 0);
}

TEST(TestJsonUtils, ArrayOfScalars)
{
    auto object = ddwaf::json_to_object("[null, true, -1, 18446744073709551615, 1.2, \"string\"]");
    EXPECT_EQ(object.type(), object_type::array);
    EXPECT_EQ(object.size(), 6);

    EXPECT_EQ(object.at(0).type(), object_type::null);

    EXPECT_EQ(object.at(1).type(), object_type::boolean);
    EXPECT_EQ(object.at(1).as<bool>(), true);

    EXPECT_EQ(object.at(2).type(), object_type::int64);
    EXPECT_EQ(object.at(2).as<int64_t>(), -1);

    EXPECT_EQ(object.at(3).type(), object_type::uint64);
    EXPECT_EQ(object.at(3).as<uint64_t>(), 18446744073709551615ULL);

    EXPECT_EQ(object.at(4).type(), object_type::float64);
    EXPECT_EQ(object.at(4).as<double>(), 1.2);

    EXPECT_EQ(object.at(5).type(), object_type::string);
    EXPECT_STRV(object.at(5).as<std::string_view>(), "string");
}

TEST(TestJsonUtils, NestedArray)
{
    std::string json_str =
        R"([null,true,-1,18446744073709551615,1.2,"string",["array",["array"],{"map":true}],{"map":{"map":-42},"array":["array",{"map":1729}]}])";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object.ref(), json_str);
}

TEST(TestJsonUtils, NestedEmptyArraysHardcodedLimit)
{
    std::string json_str = R"([[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]])";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object.ref(), R"([[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]])");
}

TEST(TestJsonUtils, EmptyMap)
{
    auto object = ddwaf::json_to_object("{}");
    EXPECT_EQ(object.type(), object_type::map);
    EXPECT_EQ(object.size(), 0);
}

TEST(TestJsonUtils, MapOfScalars)
{
    auto object = ddwaf::json_to_object(
        R"({"null":null,"bool":true,"int":-1,"uint":18446744073709551615,"double":1.2,"string":"string"})");
    EXPECT_EQ(object.type(), object_type::map);
    EXPECT_EQ(object.size(), 6);

    object_view view = object;
    {
        auto [key, child] = view.at(0);
        EXPECT_EQ(child.type(), object_type::null);

        EXPECT_STRV(key.as<std::string_view>(), "null");
    }

    {
        auto [key, child] = view.at(1);
        EXPECT_EQ(child.type(), object_type::boolean);
        EXPECT_EQ(child.as<bool>(), true);

        EXPECT_STRV(key.as<std::string_view>(), "bool");
    }

    {
        auto [key, child] = view.at(2);
        EXPECT_EQ(child.type(), object_type::int64);
        EXPECT_EQ(child.as<int64_t>(), -1);

        EXPECT_STRV(key.as<std::string_view>(), "int");
    }

    {
        auto [key, child] = view.at(3);
        EXPECT_EQ(child.type(), object_type::uint64);
        EXPECT_EQ(child.as<uint64_t>(), 18446744073709551615ULL);

        EXPECT_STRV(key.as<std::string_view>(), "uint");
    }

    {
        auto [key, child] = view.at(4);
        EXPECT_EQ(child.type(), object_type::float64);
        EXPECT_EQ(child.as<double>(), 1.2);

        EXPECT_STRV(key.as<std::string_view>(), "double");
    }

    {
        auto [key, child] = view.at(5);
        EXPECT_EQ(child.type(), object_type::string);
        EXPECT_STRV(child.as<std::string_view>(), "string");

        EXPECT_STRV(key.as<std::string_view>(), "string");
    }
}

TEST(TestJsonUtils, NestedMap)
{
    std::string json_str =
        R"({"null":null,"bool":true,"int":-1,"uint":18446744073709551615,"double":1.2,"string":"string","array":["array",["array"],{"map":true}],"map":{"map":{"map":-42},"array":["array",{"map":1729}]}})";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object.ref(), json_str);
}

TEST(TestJsonUtils, NestedEmptyMapsHardcodedLimit)
{
    std::string json_str =
        R"({"0":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"15":{"16":{"17":{"18":{"19":{"20":{}}}}}}}}}}}}}}}}}}}}}})";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object.ref(),
        R"({"0":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"15":{"16":{"17":{"18":{"19":{}}}}}}}}}}}}}}}}}}}}})");
}

TEST(TestJsonUtils, InvalidJson)
{
    std::string json_str =
        R"([null,true,-1,18446744073709551615,1.2,"string",["array",["array"],{"map":true}],{"map":{"map":-42},"array":])";

    auto object = ddwaf::json_to_object(json_str);
    EXPECT_EQ(object.type(), object_type::invalid);
}

} // namespace
