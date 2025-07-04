// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "object.hpp"
#include <stdexcept>

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestObject, NullBorrowedObject)
{
    EXPECT_THROW(borrowed_object{nullptr}, std::invalid_argument);
}

TEST(TestObject, InvalidObject)
{
    owned_object ow;
    EXPECT_EQ(ow.type(), object_type::invalid);
    EXPECT_TRUE(ow.is_invalid());
    EXPECT_FALSE(ow.is_valid());
    EXPECT_NE(ow.ptr(), nullptr);
}

TEST(TestObject, NullObject)
{
    {
        auto ow = owned_object::make_null();
        EXPECT_EQ(ow.type(), object_type::null);
    }

    {
        owned_object ow{nullptr};
        EXPECT_EQ(ow.type(), object_type::null);
    }
}

TEST(TestObject, BooleanObject)
{
    {
        auto ow = owned_object::make_boolean(true);
        EXPECT_EQ(ow.type(), object_type::boolean);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_TRUE(ow.as<bool>());
    }

    {
        owned_object ow{true};
        EXPECT_EQ(ow.type(), object_type::boolean);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_TRUE(ow.as<bool>());
    }
}

TEST(TestObject, SignedObject)
{
    {
        auto ow = owned_object::make_signed(-20);
        EXPECT_EQ(ow.type(), object_type::int64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<int64_t>(), -20);
    }

    {
        owned_object ow{-20L};
        EXPECT_EQ(ow.type(), object_type::int64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<int64_t>(), -20);
    }
}

TEST(TestObject, UnsignedObject)
{
    {
        auto ow = owned_object::make_unsigned(20);
        EXPECT_EQ(ow.type(), object_type::uint64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<uint64_t>(), 20);
    }

    {
        owned_object ow(20UL);
        EXPECT_EQ(ow.type(), object_type::uint64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<uint64_t>(), 20);
    }
}

TEST(TestObject, FloatObject)
{
    {
        auto ow = owned_object::make_float(20.5);
        EXPECT_EQ(ow.type(), object_type::float64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<double>(), 20.5);
    }

    {
        owned_object ow{20.5};
        EXPECT_EQ(ow.type(), object_type::float64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<double>(), 20.5);
    }
}

TEST(TestObject, StringObject)
{
    {
        auto ow = owned_object::make_string("this is a string");
        EXPECT_EQ(ow.type(), object_type::string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
    }

    {
        owned_object ow{"this is a string"};
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
    }
}

TEST(TestObject, SmallStringObject)
{
    {
        auto ow = owned_object::make_string("string");
        EXPECT_EQ(ow.type(), object_type::small_string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "string");
    }

    {
        owned_object ow{"string"};
        EXPECT_EQ(ow.type(), object_type::small_string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "string");
    }
}

TEST(TestObject, StringLiteralObject)
{
    auto ow = owned_object::make_string_literal(STRL("this is a string"));
    EXPECT_EQ(ow.type(), object_type::literal_string);
    EXPECT_TRUE(ow.is_string());
    EXPECT_TRUE(ow.is_valid());
    EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
}

TEST(TestObject, ArrayObjectInitializer)
{
    auto root = owned_object::make_array({"hello", "this", "is", "an", "array"});
    EXPECT_EQ(root.type(), object_type::array);
    EXPECT_TRUE(root.is_valid());
    EXPECT_EQ(root.size(), 5);
}

TEST(TestObject, MapObjectInitializer)
{
    auto root = owned_object::make_map({{"hello"sv, owned_object::make_array({"array", "value"})},
        {"this"sv, "is"sv}, {"an"sv, "array"sv}});
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());
    EXPECT_EQ(root.size(), 3);
}

TEST(TestObject, ArrayObject)
{
    auto root = owned_object::make_array();
    EXPECT_EQ(root.type(), object_type::array);
    EXPECT_TRUE(root.is_valid());

    for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::array);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_TRUE(view.is_array());

    EXPECT_EQ(view.ptr(), root.ptr());

    for (unsigned i = 0; i < 20; i++) {
        auto expected_value = std::to_string(100 + i);
        {
            auto [key, value] = view.at(i);
            EXPECT_FALSE(key.has_value());
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto value = view.at_value(i);
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto key = view.at_key(i);
            EXPECT_FALSE(key.has_value());
        }
    }
}

TEST(TestObject, MapObject)
{
    auto root = owned_object::make_map();
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());

    for (unsigned i = 0; i < 20; i++) { root.emplace(std::to_string(i), std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_TRUE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_EQ(view.ptr(), root.ptr());

    for (unsigned i = 0; i < 20; i++) {
        auto expected_key = std::to_string(i);
        auto expected_value = std::to_string(100 + i);
        {
            auto [key, value] = view.at(i);
            EXPECT_EQ(key.as<std::string_view>(), expected_key);
            EXPECT_EQ(value.as<std::string_view>(), expected_value);
        }

        {
            auto value = view.at_value(i);
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto key = view.at_key(i);
            EXPECT_EQ(key.as<std::string_view>(), expected_key);
        }
    }
}

TEST(TestObject, CloneInvalid)
{
    owned_object input;
    auto output = input.clone();
    EXPECT_TRUE(output.is_invalid());
}

TEST(TestObject, CloneNull)
{
    auto input = owned_object::make_null();

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::null);
}

TEST(TestObject, CloneBool)
{
    auto input = owned_object::make_boolean(true);

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::boolean);
    EXPECT_EQ(output.as<bool>(), true);
}

TEST(TestObject, CloneSigned)
{
    auto input = owned_object::make_signed(-5);
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::int64);
    EXPECT_EQ(output.as<int64_t>(), -5);
}

TEST(TestObject, CloneUnsigned)
{
    auto input = owned_object::make_unsigned(5);
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::uint64);
    EXPECT_EQ(output.as<uint64_t>(), 5);
}

TEST(TestObject, CloneFloat)
{
    auto input = owned_object::make_float(5.1);
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::float64);
    EXPECT_EQ(output.as<double>(), 5.1);
}

TEST(TestObject, CloneString)
{
    auto input = owned_object::make_string("this is a string");
    auto output = input.clone();
    EXPECT_TRUE(output.is_string());
    EXPECT_EQ(input.as<std::string_view>(), output.as<std::string_view>());
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneEmptyArray)
{
    auto input = owned_object::make_array();
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::array);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneEmptyMap)
{
    auto input = owned_object::make_map();
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneArray)
{
    auto input = owned_object::make_array();
    input.emplace_back(true);
    input.emplace_back("string");
    input.emplace_back(5L);

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::array);
    EXPECT_EQ(input.size(), output.size());

    {
        auto input_child = input.at(0);
        auto output_child = output.at(0);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto input_child = input.at(1);
        auto output_child = output.at(1);

        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto input_child = input.at(2);
        auto output_child = output.at(2);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }
}

TEST(TestObject, CloneMap)
{
    auto input = owned_object::make_map({{"bool", true}, {"string", "string"}, {"signed", 5}});

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());

    {
        auto input_child = input.at(0);
        auto output_child = output.at(0);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto input_child = input.at(1);
        auto output_child = output.at(1);

        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto input_child = input.at(2);
        auto output_child = output.at(2);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }
}

} // namespace
