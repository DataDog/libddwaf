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

    object_view view(original);

    EXPECT_EQ(view.type(), object_type::invalid);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_FALSE(view.as<bool>());
    EXPECT_FALSE(view.as<int64_t>());
    EXPECT_FALSE(view.as<uint64_t>());
    EXPECT_FALSE(view.as<double>());

    EXPECT_FALSE(view.as<std::string>());
    EXPECT_FALSE(view.as<std::string_view>());
    EXPECT_FALSE(view.as<const char *>());
}

TEST(TestObjectView, NullObject)
{
    detail::object original;
    ddwaf_object_invalid(&original);

    object_view view(original);

    EXPECT_EQ(view.type(), object_type::invalid);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_FALSE(view.as<bool>());

    EXPECT_FALSE(view.as<int64_t>());
    EXPECT_FALSE(view.as<uint64_t>());
    EXPECT_FALSE(view.as<double>());

    EXPECT_FALSE(view.as<std::string>());
    EXPECT_FALSE(view.as<std::string_view>());
    EXPECT_FALSE(view.as<const char *>());
}

TEST(TestObjectView, BooleanObject)
{
    detail::object original;
    ddwaf_object_bool(&original, true);

    object_view view(original);

    EXPECT_EQ(view.type(), object_type::boolean);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_TRUE(view.as<bool>());
    EXPECT_EQ(view.as<bool>().value(), true);

    EXPECT_EQ(view.as_unchecked<bool>(), true);

    EXPECT_FALSE(view.as<int64_t>());
    EXPECT_FALSE(view.as<uint64_t>());
    EXPECT_FALSE(view.as<double>());

    EXPECT_FALSE(view.as<std::string>());
    EXPECT_FALSE(view.as<std::string_view>());
    EXPECT_FALSE(view.as<const char *>());
}

TEST(TestObjectView, SignedObject)
{
    detail::object original;
    ddwaf_object_signed(&original, -20);

    object_view view(original);

    EXPECT_EQ(view.type(), object_type::int64);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_TRUE(view.as<int64_t>());
    EXPECT_EQ(view.as<int64_t>().value(), -20);

    EXPECT_EQ(view.as_unchecked<int64_t>(), -20);

    EXPECT_FALSE(view.as<bool>());
    EXPECT_FALSE(view.as<uint64_t>());
    EXPECT_FALSE(view.as<double>());

    EXPECT_FALSE(view.as<std::string>());
    EXPECT_FALSE(view.as<std::string_view>());
    EXPECT_FALSE(view.as<const char *>());
}

TEST(TestObjectView, UnsignedObject)
{
    detail::object original;
    ddwaf_object_unsigned(&original, 20);

    object_view view(original);

    EXPECT_EQ(view.type(), object_type::uint64);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_TRUE(view.as<uint64_t>());
    EXPECT_EQ(view.as<uint64_t>().value(), 20);

    EXPECT_EQ(view.as_unchecked<uint64_t>(), 20);

    EXPECT_FALSE(view.as<bool>());
    EXPECT_FALSE(view.as<int64_t>());
    EXPECT_FALSE(view.as<double>());

    EXPECT_FALSE(view.as<std::string>());
    EXPECT_FALSE(view.as<std::string_view>());
    EXPECT_FALSE(view.as<const char *>());
}

TEST(TestObjectView, FloatObject)
{
    detail::object original;
    ddwaf_object_float(&original, 20.1);

    object_view view(original);

    EXPECT_EQ(view.type(), object_type::float64);

    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    EXPECT_TRUE(view.as<double>());
    EXPECT_EQ(view.as<double>().value(), 20.1);

    EXPECT_EQ(view.as_unchecked<double>(), 20.1);

    EXPECT_FALSE(view.as<bool>());
    EXPECT_FALSE(view.as<uint64_t>());
    EXPECT_FALSE(view.as<int64_t>());

    EXPECT_FALSE(view.as<std::string>());
    EXPECT_FALSE(view.as<std::string_view>());
    EXPECT_FALSE(view.as<const char *>());
}

TEST(TestObjectView, ArrayObject)
{
    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);

    for (unsigned i = 0; i < 20; i++) {
        ddwaf_object_map_add(&root, std::to_string(i).c_str(),
            ddwaf_object_string(&tmp, std::to_string(i + 100).c_str()));
    }

    object_view view(root);
    EXPECT_EQ(view.size(), 20);

    for (unsigned i = 0; i < 20; i++) {
        auto [key, value] = view.at_unchecked(i);
        EXPECT_STREQ(value->as_unchecked<const char *>(), std::to_string(100 + i).c_str());
    }

    ddwaf_object_free(&root);
}

} // namespace
