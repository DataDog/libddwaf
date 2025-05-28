// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "object.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestObjectView, DefaultObject)
{
    object_view view;
    EXPECT_FALSE(view.has_value());
}

TEST(TestObjectView, InvalidObject)
{
    owned_object original;
    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::invalid);

    EXPECT_EQ(view.ptr(), original.ptr());

    EXPECT_FALSE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, NullObject)
{
    owned_object original{nullptr};

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::null);

    EXPECT_FALSE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, BooleanObject)
{
    owned_object original{true};

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::boolean);

    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_TRUE(view.is<bool>());
    EXPECT_EQ(view.as<bool>(), true);

    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, SignedObject)
{
    owned_object original{-20};

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::int64);

    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_TRUE(view.is<int64_t>());
    EXPECT_EQ(view.as<int64_t>(), -20);

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, SignedObjectCompatibility)
{
    {
        owned_object original{-1};
        object_view view(original);

        EXPECT_TRUE(view.is<int8_t>());
        EXPECT_TRUE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original{std::numeric_limits<int8_t>::min() - 1};
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_TRUE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original{std::numeric_limits<int8_t>::max() + 1};
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_TRUE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original{std::numeric_limits<int16_t>::min() - 1};
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original{std::numeric_limits<int16_t>::max() + 1};
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original{static_cast<int64_t>(std::numeric_limits<int32_t>::min()) - 1};
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_FALSE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original{static_cast<int64_t>(std::numeric_limits<int32_t>::max()) + 1};
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_FALSE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }
}

TEST(TestObjectView, UnsignedObject)
{
    owned_object original{20UL};
    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::uint64);

    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_TRUE(view.is<uint64_t>());
    EXPECT_EQ(view.as<uint64_t>(), 20);

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, UnsignedObjectCompatibility)
{
    {
        owned_object original{1UL};
        object_view view(original);

        EXPECT_TRUE(view.is<uint8_t>());
        EXPECT_TRUE(view.is<uint16_t>());
        EXPECT_TRUE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }

    {
        owned_object original{static_cast<uint64_t>(std::numeric_limits<uint8_t>::max() + 1)};
        object_view view(original);

        EXPECT_FALSE(view.is<uint8_t>());
        EXPECT_TRUE(view.is<uint16_t>());
        EXPECT_TRUE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }

    {
        owned_object original{static_cast<uint64_t>(std::numeric_limits<uint16_t>::max() + 1)};
        object_view view(original);

        EXPECT_FALSE(view.is<uint8_t>());
        EXPECT_FALSE(view.is<uint16_t>());
        EXPECT_TRUE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }

    {
        owned_object original{static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1};
        object_view view(original);

        EXPECT_FALSE(view.is<uint8_t>());
        EXPECT_FALSE(view.is<uint16_t>());
        EXPECT_FALSE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }
}
TEST(TestObjectView, FloatObject)
{
    owned_object original{20.1};
    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::float64);

    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_TRUE(view.is<double>());
    EXPECT_EQ(view.as<double>(), 20.1);

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<int64_t>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, StringObject)
{
    owned_object original{"string_value"};

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::string);

    EXPECT_EQ(view.size(), sizeof("string_value") - 1);
    EXPECT_FALSE(view.empty());
    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_TRUE(view.is<std::string>());
    EXPECT_TRUE(view.is<std::string_view>());
    EXPECT_TRUE(view.is<const char *>());
}

TEST(TestObjectView, ArrayObject)
{
    auto root = owned_object::make_array();
    for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::array);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_TRUE(view.is_array());

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

TEST(TestObjectView, MapObject)
{
    auto root = owned_object::make_map();
    for (unsigned i = 0; i < 20; i++) { root.emplace(std::to_string(i), std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_TRUE(view.is_map());
    EXPECT_FALSE(view.is_array());

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

TEST(TestObjectView, Equality)
{
    owned_object root;
    object_view view(root);

    {
        object_view view2(root);
        EXPECT_TRUE(view == view2);
        EXPECT_TRUE(view2 == view);
    }

    {
        owned_object other;
        object_view view2(other);

        EXPECT_FALSE(view == view2);
        EXPECT_FALSE(view2 == view);
    }

    {
        object_view view2;
        EXPECT_FALSE(view == view2);
        EXPECT_FALSE(view2 == view);
    }
}

TEST(TestObjectView, Inequality)
{
    owned_object root;
    object_view view(root);

    {
        object_view view2(root);
        EXPECT_FALSE(view != view2);
        EXPECT_FALSE(view2 != view);
    }

    {
        owned_object other;
        object_view view2(other);

        EXPECT_TRUE(view != view2);
        EXPECT_TRUE(view2 != view);
    }

    {
        object_view view2;
        EXPECT_TRUE(view != view2);
        EXPECT_TRUE(view2 != view);
    }
}

TEST(TestObjectView, StringEquality)
{
    owned_object root{"something"};

    object_view view(root);

    EXPECT_TRUE(view == "something"sv);
    EXPECT_FALSE(view == "something else"sv);
}

TEST(TestObjectView, StringInequality)
{
    owned_object root{"something"};

    object_view view(root);

    EXPECT_TRUE(view != "something else"sv);
    EXPECT_FALSE(view != "something"sv);
}

TEST(TestObjectView, BooleanObjectStringConversion)
{
    {
        owned_object original{true};
        object_view view(original);
        auto converted = view.convert<std::string>();
        EXPECT_STR(converted, "true");
    }

    {
        owned_object original{false};
        object_view view(original);
        auto converted = view.convert<std::string>();
        EXPECT_STR(converted, "false");
    }
}

TEST(TestObjectView, SignedObjectStringConversion)
{
    owned_object original{-123456};
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "-123456");
}

TEST(TestObjectView, UnsignedObjectStringConversion)
{
    owned_object original{123456UL};
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "123456");
}

TEST(TestObjectView, FloatObjectStringConversion)
{
    owned_object original{20.1};
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "20.1");
}

TEST(TestObjectView, StringtObjectStringConversion)
{
    owned_object original{"this is a string"};
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "this is a string");
}

TEST(TestObjectView, AsOrDefault)
{
    owned_object original;
    object_view view(original);

    EXPECT_EQ(view.as_or_default<std::string_view>({}), std::string_view{});
    EXPECT_EQ(view.as_or_default<double>(20.1), 20.1);
    EXPECT_EQ(view.as_or_default<uint64_t>(0), 0);
    EXPECT_EQ(view.as_or_default<int64_t>(0), 0);
    EXPECT_EQ(view.as_or_default<bool>(false), false);
}

TEST(TestObjectView, CloneInvalid)
{
    owned_object input_data;
    object_view input{input_data};
    auto output = input.clone();
    EXPECT_TRUE(output.is_invalid());
}

TEST(TestObjectView, CloneNull)
{
    auto input_data = owned_object::make_null();
    object_view input{input_data};

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::null);
}

TEST(TestObjectView, CloneBool)
{
    auto input_data = owned_object::make_boolean(true);
    object_view input{input_data};

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::boolean);
    EXPECT_EQ(output.as<bool>(), true);
}

TEST(TestObjectView, CloneSigned)
{
    auto input_data = owned_object::make_signed(-5);
    object_view input{input_data};

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::int64);
    EXPECT_EQ(output.as<int64_t>(), -5);
}

TEST(TestObjectView, CloneUnsigned)
{
    auto input_data = owned_object::make_unsigned(5);
    object_view input{input_data};

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::uint64);
    EXPECT_EQ(output.as<uint64_t>(), 5);
}

TEST(TestObjectView, CloneFloat)
{
    auto input_data = owned_object::make_float(5.1);
    object_view input{input_data};

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::float64);
    EXPECT_EQ(output.as<double>(), 5.1);
}

TEST(TestObjectView, CloneString)
{
    auto input_data = owned_object::make_string("this is a string");
    object_view input{input_data};

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::string);
    EXPECT_EQ(input.as<std::string_view>(), output.as<std::string_view>());
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObjectView, CloneEmptyArray)
{
    auto input_data = owned_object::make_array();
    object_view input{input_data};

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::array);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObjectView, CloneEmptyMap)
{
    auto input_data = owned_object::make_map();
    object_view input{input_data};

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObjectView, CloneArray)
{
    auto input_data = owned_object::make_array();
    input_data.emplace_back(owned_object::make_boolean(true));
    input_data.emplace_back(owned_object::make_string("string"));
    input_data.emplace_back(owned_object::make_signed(5));
    object_view input{input_data};

    auto output_data = input.clone();
    object_view output{output_data};

    EXPECT_EQ(output.type(), object_type::array);
    EXPECT_EQ(input.size(), output.size());

    {
        auto [input_key, input_child] = input.at(0);
        auto [output_key, output_child] = output.at(0);

        EXPECT_FALSE(output_key.has_value());
        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto [input_key, input_child] = input.at(1);
        auto [output_key, output_child] = output.at(1);

        EXPECT_FALSE(output_key.has_value());
        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto [input_key, input_child] = input.at(2);
        auto [output_key, output_child] = output.at(2);

        EXPECT_FALSE(output_key.has_value());
        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }
}

TEST(TestObjectView, CloneMap)
{
    owned_object input_data = owned_object::make_map();
    input_data.emplace("bool", owned_object::make_boolean(true));
    input_data.emplace("string", owned_object::make_string("string"));
    input_data.emplace("signed", owned_object::make_signed(5));
    object_view input{input_data};

    auto output_data = input.clone();
    object_view output{output_data};

    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());

    {
        auto [input_key, input_child] = input.at(0);
        auto [output_key, output_child] = output.at(0);

        EXPECT_EQ(input_key.as<std::string_view>(), output_key.as<std::string_view>());
        EXPECT_NE(input_key.data(), output_key.data());
        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto [input_key, input_child] = input.at(1);
        auto [output_key, output_child] = output.at(1);

        EXPECT_EQ(input_key.as<std::string_view>(), output_key.as<std::string_view>());
        EXPECT_NE(input_key.data(), output_key.data());

        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto [input_key, input_child] = input.at(2);
        auto [output_key, output_child] = output.at(2);

        EXPECT_EQ(input_key.as<std::string_view>(), output_key.as<std::string_view>());
        EXPECT_NE(input_key.data(), output_key.data());

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }
}

} // namespace
