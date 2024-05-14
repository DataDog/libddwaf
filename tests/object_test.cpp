// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <gtest/gtest.h>
#include <string_view>

#include "object.hpp"
#include "object_view.hpp"

#define EXPECT_SVEQ(obtained, expected) \
    EXPECT_TRUE(obtained == std::string_view{expected})

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(Object, InvalidConstructor)
{
    owned_object obj;

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::invalid);
}

TEST(Object, NullConstructor)
{
    owned_object obj = owned_object::make_null();

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::null);
}

TEST(Object, BooleanConstructor)
{
    {
        owned_object obj = owned_object::make_boolean(true);

        object_view view{obj};
        EXPECT_EQ(view.type(), object_type::boolean);
        EXPECT_TRUE(view.as_unchecked<bool>());
    }
    {
        owned_object obj = owned_object::make_boolean(false);

        object_view view{obj};
        EXPECT_EQ(view.type(), object_type::boolean);
        EXPECT_FALSE(view.as_unchecked<bool>());
    }
}

TEST(Object, UnsignedConstructor)
{
    {
        owned_object obj = owned_object::make_unsigned(42);

        object_view view{obj};
        EXPECT_EQ(view.type(), object_type::uint64);
        EXPECT_EQ(view.as<unsigned>(), 42);
    }
    {
        auto value = std::numeric_limits<uint64_t>::max();
        owned_object obj = owned_object::make_unsigned(value);

        object_view view{obj};
        EXPECT_EQ(view.type(), object_type::uint64);
        EXPECT_EQ(view.as<uint64_t>(), value);
    }
}

TEST(Object, SignedConstructor)
{
    {
        owned_object obj = owned_object::make_signed(-42);

        object_view view{obj};
        EXPECT_EQ(view.type(), object_type::int64);
        EXPECT_EQ(view.as<int>(), -42);
    }
    {
        auto value = std::numeric_limits<int64_t>::min();
        owned_object obj = owned_object::make_signed(value);

        object_view view{obj};
        EXPECT_EQ(view.type(), object_type::int64);
        EXPECT_EQ(view.as<int64_t>(), value);
    }
}

TEST(Object, FloatConstructor)
{
    {
        auto value = std::numeric_limits<double>::min();
        owned_object obj = owned_object::make_float(value);

        object_view view{obj};
        EXPECT_EQ(view.type(), object_type::float64);
        EXPECT_EQ(view.as<double>(), value);
    }

    {
        auto value = std::numeric_limits<float>::min();
        owned_object obj = owned_object::make_float(value);

        object_view view{obj};
        EXPECT_EQ(view.type(), object_type::float64);
        EXPECT_EQ(view.as<float>(), value);
    }
}

TEST(Object, ConstStringConstructor)
{
    auto value = "hello"sv;
    owned_object obj = owned_object::make_const_string(value.data(), value.size());

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::const_string);
    EXPECT_SVEQ(view.as<std::string_view>(), "hello");
    EXPECT_EQ(view.length(), value.size());
}

TEST(Object, ConstStringViewConstructor)
{
    auto value = "hello"sv;
    owned_object obj = owned_object::make_const_string(value);

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::const_string);
    EXPECT_SVEQ(view.as<std::string_view>(), "hello");
    EXPECT_EQ(view.length(), value.size());
}

TEST(Object, SmallStringConstructor)
{
    auto value = "hello"sv;
    owned_object obj = owned_object::make_string(value.data(), value.size());

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::small_string);
    EXPECT_SVEQ(view.as<std::string_view>(), "hello");
    EXPECT_EQ(view.length(), value.size());
}

TEST(Object, SmallStringViewConstructor)
{
    auto value = "hello"sv;
    owned_object obj = owned_object::make_string(value);

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::small_string);
    EXPECT_SVEQ(view.as<std::string_view>(), "hello");
    EXPECT_EQ(view.length(), value.size());
}

TEST(Object, StringConstructor)
{
    auto value = "hello world!"sv;
    owned_object obj = owned_object::make_string(value.data(), value.size());

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::string);
    EXPECT_SVEQ(view.as<std::string_view>(), "hello world!");
    EXPECT_EQ(view.length(), value.size());
}

TEST(Object, StringViewConstructor)
{
    auto value = "hello world!"sv;
    owned_object obj = owned_object::make_string(value);

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::string);
    EXPECT_SVEQ(view.as<std::string_view>(), "hello world!");
    EXPECT_EQ(view.length(), value.size());
}

TEST(Object, ArrayConstructor)
{
    owned_object obj = owned_object::make_array(8);

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::array);
    EXPECT_EQ(view.size(), 0);
    EXPECT_EQ(view.capacity(), 8);

    auto array_view = view.as_unchecked<object_view::array>();
    EXPECT_EQ(array_view.size(), 0);
    EXPECT_EQ(array_view.capacity(), 8);
}

TEST(Object, MapConstructor)
{
    owned_object obj = owned_object::make_map(8);

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_EQ(view.size(), 0);
    EXPECT_EQ(view.capacity(), 8);

    auto map_view = view.as_unchecked<object_view::map>();
    EXPECT_EQ(map_view.size(), 0);
    EXPECT_EQ(map_view.capacity(), 8);
}

TEST(Object, ArrayEmplaceBack)
{
    unsigned count = 8;
    owned_object obj = owned_object::make_array(count);
    while (count--) {
        auto slot = obj.emplace_back({});
        EXPECT_TRUE(slot.has_value());
    }

    {
        auto slot = obj.emplace_back({});
        EXPECT_FALSE(slot.has_value());
    }

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::array);
    EXPECT_EQ(view.size(), 8);
    EXPECT_EQ(view.capacity(), 8);

    auto array_view = view.as_unchecked<object_view::array>();
    EXPECT_EQ(array_view.size(), 8);
    EXPECT_EQ(array_view.capacity(), 8);
    for (auto value : array_view) {
        EXPECT_EQ(value.type(), object_type::invalid);
    }
}

TEST(Object, MapEmplaceStringViewKey)
{
    unsigned count = 8;
    owned_object obj = owned_object::make_map(count);
    while ((count--) != 0) {
        auto slot = obj.emplace("key"sv, {});
        EXPECT_TRUE(slot.has_value());
    }

    {
        auto slot = obj.emplace("key"sv, {});
        EXPECT_FALSE(slot.has_value());
    }

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_EQ(view.size(), 8);
    EXPECT_EQ(view.capacity(), 8);

    auto map_view = view.as_unchecked<object_view::map>();
    EXPECT_EQ(map_view.size(), 8);
    EXPECT_EQ(map_view.capacity(), 8);
    for (auto [key, value] : map_view) {
        EXPECT_SVEQ(key, "key");
        EXPECT_EQ(value.type(), object_type::invalid);
    }
}

TEST(Object, MapEmplaceObjectKey)
{
    unsigned count = 8;
    owned_object obj = owned_object::make_map(count);
    while ((count--) != 0) {
        auto slot = obj.emplace(owned_object::make_string("key"sv), {});
        EXPECT_TRUE(slot.has_value());
    }

    {
        auto slot = obj.emplace(owned_object::make_string("key"sv), {});
        EXPECT_FALSE(slot.has_value());
    }

    object_view view{obj};
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_EQ(view.size(), 8);
    EXPECT_EQ(view.capacity(), 8);

    auto map_view = view.as_unchecked<object_view::map>();
    EXPECT_EQ(map_view.size(), 8);
    EXPECT_EQ(map_view.capacity(), 8);
    for (auto [key, value] : map_view) {
        EXPECT_SVEQ(key, "key");
        EXPECT_EQ(value.type(), object_type::invalid);
    }
}

} // namespace
