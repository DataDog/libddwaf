// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "object_view.hpp"
#include "test_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestObjectView, InvalidObject)
{
    detail::object original;
    ddwaf_object_invalid(&original);

    object_view view(&original);
    EXPECT_TRUE(view.has_value());

    EXPECT_EQ(view.type(), object_type::invalid);
    EXPECT_EQ(view.type_unchecked(), object_type::invalid);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_FALSE(view.as<bool>());
    EXPECT_FALSE(view.as<int64_t>());
    EXPECT_FALSE(view.as<uint64_t>());
    EXPECT_FALSE(view.as<double>());
    EXPECT_FALSE(view.as<std::string>());
}

TEST(TestObjectView, NullObject)
{
    detail::object original;
    ddwaf_object_invalid(&original);

    object_view view(&original);
    EXPECT_TRUE(view.has_value());

    EXPECT_EQ(view.type(), object_type::invalid);
    EXPECT_EQ(view.type_unchecked(), object_type::invalid);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_FALSE(view.as<bool>());
    EXPECT_FALSE(view.as<int64_t>());
    EXPECT_FALSE(view.as<uint64_t>());
    EXPECT_FALSE(view.as<double>());
    EXPECT_FALSE(view.as<std::string>());
}

TEST(TestObjectView, BooleanObject)
{
    detail::object original;
    ddwaf_object_bool(&original, true);

    object_view view(&original);
    EXPECT_TRUE(view.has_value());

    EXPECT_EQ(view.type(), object_type::boolean);
    EXPECT_EQ(view.type_unchecked(), object_type::boolean);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_TRUE(view.as<bool>());
    EXPECT_EQ(view.as<bool>().value(), true);

    EXPECT_EQ(view.as_unchecked<bool>(), true);

    EXPECT_FALSE(view.as<int64_t>());
    EXPECT_FALSE(view.as<uint64_t>());
    EXPECT_FALSE(view.as<double>());
    EXPECT_FALSE(view.as<std::string>());
}

TEST(TestObjectView, SignedObject)
{
    detail::object original;
    ddwaf_object_signed(&original, -20);

    object_view view(&original);
    EXPECT_TRUE(view.has_value());

    EXPECT_EQ(view.type(), object_type::int64);
    EXPECT_EQ(view.type_unchecked(), object_type::int64);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_TRUE(view.as<int64_t>());
    EXPECT_EQ(view.as<int64_t>().value(), -20);

    EXPECT_EQ(view.as_unchecked<int64_t>(), -20);

    EXPECT_FALSE(view.as<bool>());
    EXPECT_FALSE(view.as<uint64_t>());
    EXPECT_FALSE(view.as<double>());
    EXPECT_FALSE(view.as<std::string>());
}

TEST(TestObjectView, UnsignedObject)
{
    detail::object original;
    ddwaf_object_unsigned(&original, 20);

    object_view view(&original);
    EXPECT_TRUE(view.has_value());

    EXPECT_EQ(view.type(), object_type::uint64);
    EXPECT_EQ(view.type_unchecked(), object_type::uint64);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_TRUE(view.as<uint64_t>());
    EXPECT_EQ(view.as<uint64_t>().value(), 20);

    EXPECT_EQ(view.as_unchecked<uint64_t>(), 20);

    EXPECT_FALSE(view.as<bool>());
    EXPECT_FALSE(view.as<int64_t>());
    EXPECT_FALSE(view.as<double>());
    EXPECT_FALSE(view.as<std::string>());
}

} // namespace
