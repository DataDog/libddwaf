// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "object.hpp"
#include "object_view.hpp"
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
    auto ow = owned_object::make_null();
    EXPECT_EQ(ow.type(), object_type::null);
}

TEST(TestObject, BooleanObject)
{
    auto ow = owned_object::make_boolean(true);
    EXPECT_EQ(ow.type(), object_type::boolean);
    EXPECT_TRUE(ow.is_valid());

    object_view ov{ow};
    EXPECT_EQ(ov.type(), object_type::boolean);
    EXPECT_TRUE(ov.as<bool>());
}

TEST(TestObject, SignedObject)
{
    auto ow = owned_object::make_signed(-20);
    EXPECT_EQ(ow.type(), object_type::int64);
    EXPECT_TRUE(ow.is_valid());

    object_view ov{ow};
    EXPECT_EQ(ov.type(), object_type::int64);
    EXPECT_EQ(ov.as<int64_t>(), -20);
}

TEST(TestObject, UnsignedObject)
{
    auto ow = owned_object::make_unsigned(20);
    EXPECT_EQ(ow.type(), object_type::uint64);
    EXPECT_TRUE(ow.is_valid());

    object_view ov{ow};
    EXPECT_EQ(ov.type(), object_type::uint64);
    EXPECT_EQ(ov.as<uint64_t>(), 20);
}

TEST(TestObject, FloatObject)
{
    auto ow = owned_object::make_float(20.5);
    EXPECT_EQ(ow.type(), object_type::float64);
    EXPECT_TRUE(ow.is_valid());

    object_view ov{ow};
    EXPECT_EQ(ov.type(), object_type::float64);
    EXPECT_EQ(ov.as<double>(), 20.5);
}

TEST(TestObject, StringObject)
{
    auto ow = owned_object::make_string("this is a string");
    EXPECT_EQ(ow.type(), object_type::string);
    EXPECT_TRUE(ow.is_valid());

    object_view ov{ow};
    EXPECT_EQ(ov.type(), object_type::string);
    EXPECT_EQ(ov.as<std::string_view>(), "this is a string");
}

TEST(TestObject, ArrayObject)
{
    auto root = owned_object::make_array();
    EXPECT_EQ(root.type(), object_type::array);
    EXPECT_TRUE(root.is_valid());

    for (unsigned i = 0; i < 20; i++) {
        root.emplace_back(owned_object::make_string(std::to_string(i + 100)));
    }

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
            EXPECT_TRUE(key.empty());
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto value = view.at_value(i);
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto key = view.at_key(i);
            EXPECT_TRUE(key.empty());
        }
    }
}

TEST(TestObject, MapObject)
{
    auto root = owned_object::make_map();
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());

    for (unsigned i = 0; i < 20; i++) {
        root.emplace(std::to_string(i), owned_object::make_string(std::to_string(i + 100)));
    }

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

/*TEST(TestObject, EmplaceWrongObject)*/
/*{*/
/*owned_object container;*/
/*EXPECT_THROW(container.emplace("key", owned_object::make_string("value")), std::out_of_range);*/
/*}*/

/*TEST(TestObject, EmplaceBackWrongObject)*/
/*{*/
/*owned_object container;*/
/*EXPECT_THROW(container.emplace_back(owned_object::make_string("value")), std::out_of_range);*/
/*}*/

} // namespace
