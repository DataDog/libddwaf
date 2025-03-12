// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "object_converter.hpp"
#include "object_view.hpp"

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
    detail::object original;
    ddwaf_object_invalid(&original);

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::invalid);

    EXPECT_EQ(view.ptr(), &original);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());
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
    detail::object original;
    ddwaf_object_invalid(&original);

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::invalid);

    EXPECT_EQ(view.ptr(), &original);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());
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
    detail::object original;
    ddwaf_object_bool(&original, true);

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::boolean);

    EXPECT_EQ(view.ptr(), &original);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());
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
    detail::object original;
    ddwaf_object_signed(&original, -20);

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::int64);

    EXPECT_EQ(view.ptr(), &original);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());
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
        detail::object original;
        ddwaf_object_signed(&original, -1);
        object_view view(original);

        EXPECT_TRUE(view.is<int8_t>());
        EXPECT_TRUE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        detail::object original;
        ddwaf_object_signed(&original, std::numeric_limits<int8_t>::min() - 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_TRUE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        detail::object original;
        ddwaf_object_signed(&original, std::numeric_limits<int8_t>::max() + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_TRUE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        detail::object original;
        ddwaf_object_signed(&original, std::numeric_limits<int16_t>::min() - 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        detail::object original;
        ddwaf_object_signed(&original, std::numeric_limits<int16_t>::max() + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        detail::object original;
        ddwaf_object_signed(
            &original, static_cast<int64_t>(std::numeric_limits<int32_t>::min()) - 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_FALSE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        detail::object original;
        ddwaf_object_signed(
            &original, static_cast<int64_t>(std::numeric_limits<int32_t>::max()) + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_FALSE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }
}

TEST(TestObjectView, UnsignedObject)
{
    detail::object original;
    ddwaf_object_unsigned(&original, 20);

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::uint64);

    EXPECT_EQ(view.ptr(), &original);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());
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
        detail::object original;
        ddwaf_object_unsigned(&original, 1);
        object_view view(original);

        EXPECT_TRUE(view.is<uint8_t>());
        EXPECT_TRUE(view.is<uint16_t>());
        EXPECT_TRUE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }

    {
        detail::object original;
        ddwaf_object_unsigned(&original, std::numeric_limits<uint8_t>::max() + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<uint8_t>());
        EXPECT_TRUE(view.is<uint16_t>());
        EXPECT_TRUE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }

    {
        detail::object original;
        ddwaf_object_unsigned(&original, std::numeric_limits<uint16_t>::max() + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<uint8_t>());
        EXPECT_FALSE(view.is<uint16_t>());
        EXPECT_TRUE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }

    {
        detail::object original;
        ddwaf_object_unsigned(
            &original, static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<uint8_t>());
        EXPECT_FALSE(view.is<uint16_t>());
        EXPECT_FALSE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }
}
TEST(TestObjectView, FloatObject)
{
    detail::object original;
    ddwaf_object_float(&original, 20.1);

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::float64);

    EXPECT_EQ(view.ptr(), &original);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());
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
    detail::object original;
    ddwaf_object_string(&original, "string_value");

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::string);

    EXPECT_EQ(view.ptr(), &original);

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

    ddwaf_object_free(&original);
}

TEST(TestObjectView, ArrayObject)
{
    detail::object root;
    detail::object tmp;
    ddwaf_object_array(&root);

    for (unsigned i = 0; i < 20; i++) {
        ddwaf_object_array_add(&root, ddwaf_object_string(&tmp, std::to_string(i + 100).c_str()));
    }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::array);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_TRUE(view.is_array());

    EXPECT_EQ(view.ptr(), &root);

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

    ddwaf_object_free(&root);
}

TEST(TestObjectView, MapObject)
{
    detail::object root;
    detail::object tmp;
    ddwaf_object_map(&root);

    for (unsigned i = 0; i < 20; i++) {
        ddwaf_object_map_add(&root, std::to_string(i).c_str(),
            ddwaf_object_string(&tmp, std::to_string(i + 100).c_str()));
    }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_TRUE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_EQ(view.ptr(), &root);

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

    ddwaf_object_free(&root);
}

TEST(TestObjectView, IterateArrayObject)
{
    detail::object root;
    detail::object tmp;
    ddwaf_object_array(&root);

    for (unsigned i = 0; i < 20; i++) {
        ddwaf_object_array_add(&root, ddwaf_object_string(&tmp, std::to_string(i + 100).c_str()));
    }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::array);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());

    EXPECT_EQ(view.ptr(), &root);

    for (auto it = view.begin(); it != view.end(); ++it) {
        auto expected_value = std::to_string(100 + it.index());
        {
            auto [key, value] = *it;
            EXPECT_TRUE(key.empty());
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto value = it.value();
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto key = it.key();
            EXPECT_TRUE(key.empty());
        }
    }

    ddwaf_object_free(&root);
}

TEST(TestObjectView, IterateMapObject)
{
    detail::object root;
    detail::object tmp;
    ddwaf_object_map(&root);

    for (unsigned i = 0; i < 20; i++) {
        ddwaf_object_map_add(&root, std::to_string(i).c_str(),
            ddwaf_object_string(&tmp, std::to_string(i + 100).c_str()));
    }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());

    EXPECT_EQ(view.ptr(), &root);

    for (auto it = view.begin(); it != view.end(); ++it) {
        auto expected_key = std::to_string(it.index());
        auto expected_value = std::to_string(100 + it.index());
        {
            auto [key, value] = *it;
            EXPECT_EQ(key.as<std::string_view>(), expected_key);
            EXPECT_EQ(value.as<std::string_view>(), expected_value);
        }

        {
            auto value = it.value();
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto key = it.key();
            EXPECT_EQ(key.as<std::string_view>(), expected_key);
        }
    }

    ddwaf_object_free(&root);
}

TEST(TestObjectView, Equality)
{
    detail::object root;
    ddwaf_object_invalid(&root);

    object_view view(root);

    EXPECT_TRUE(view == root);

    {
        object_view view2(root);
        EXPECT_TRUE(view == view2);
        EXPECT_TRUE(view2 == view);
    }

    {
        detail::object other;
        ddwaf_object_invalid(&other);
        object_view view2(other);

        EXPECT_FALSE(view == other);
        EXPECT_TRUE(view2 == other);

        EXPECT_FALSE(view == view2);
        EXPECT_FALSE(view2 == view);
    }

    {
        object_view view2;
        EXPECT_TRUE(view2 == nullptr);
        EXPECT_FALSE(view == view2);
        EXPECT_FALSE(view2 == view);
    }

    {
        EXPECT_FALSE(view == nullptr);
    }
}

TEST(TestObjectView, Inequality)
{
    detail::object root;
    ddwaf_object_invalid(&root);

    object_view view(root);

    EXPECT_FALSE(view != root);

    {
        object_view view2(root);
        EXPECT_FALSE(view != view2);
        EXPECT_FALSE(view2 != view);
    }

    {
        detail::object other;
        ddwaf_object_invalid(&other);
        object_view view2(other);

        EXPECT_TRUE(view != other);
        EXPECT_FALSE(view2 != other);

        EXPECT_TRUE(view != view2);
        EXPECT_TRUE(view2 != view);
    }

    {
        object_view view2;
        EXPECT_FALSE(view2 != nullptr);
        EXPECT_TRUE(view != view2);
        EXPECT_TRUE(view2 != view);
    }

    {
        EXPECT_TRUE(view != nullptr);
    }
}

TEST(TestObjectView, StringEquality)
{
    detail::object root;
    ddwaf_object_string(&root, "something");

    object_view view(root);

    EXPECT_TRUE(view == "something"sv);
    EXPECT_FALSE(view == "something else"sv);

    ddwaf_object_free(&root);
}

TEST(TestObjectView, StringInequality)
{
    detail::object root;
    ddwaf_object_string(&root, "something");

    object_view view(root);

    EXPECT_TRUE(view != "something else"sv);
    EXPECT_FALSE(view != "something"sv);

    ddwaf_object_free(&root);
}

TEST(TestObjectView, BooleanObjectStringConversion)
{
    detail::object original;
    {
        ddwaf_object_bool(&original, true);
        object_view view(original);
        auto converted = view.convert<std::string>();
        EXPECT_STR(converted, "true");
    }

    {
        ddwaf_object_bool(&original, false);
        object_view view(original);
        auto converted = view.convert<std::string>();
        EXPECT_STR(converted, "false");
    }
}

TEST(TestObjectView, SignedObjectStringConversion)
{
    detail::object original;
    ddwaf_object_signed(&original, -123456);
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "-123456");
}

TEST(TestObjectView, UnsignedObjectStringConversion)
{
    detail::object original;
    ddwaf_object_unsigned(&original, 123456);
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "123456");
}

TEST(TestObjectView, FloatObjectStringConversion)
{
    detail::object original;
    ddwaf_object_float(&original, 20.1);
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "20.1");
}

TEST(TestObjectView, StringtObjectStringConversion)
{
    detail::object original;
    ddwaf_object_string(&original, "this is a string");
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "this is a string");
    ddwaf_object_free(&original);
}

TEST(TestObjectView, AsOrDefault)
{
    detail::object original;
    ddwaf_object_invalid(&original);

    object_view view(original);

    EXPECT_EQ(view.as_or_default<std::string_view>({}), std::string_view{});
    EXPECT_EQ(view.as_or_default<double>(20.1), 20.1);
    EXPECT_EQ(view.as_or_default<uint64_t>(0), 0);
    EXPECT_EQ(view.as_or_default<int64_t>(0), 0);
    EXPECT_EQ(view.as_or_default<bool>(false), false);
}

} // namespace
