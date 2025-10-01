// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/equals.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestEqualsBool, Basic)
{
    {
        matcher::equals<bool> matcher(false);

        EXPECT_TRUE(matcher.match(false).first);
        EXPECT_FALSE(matcher.match(true).first);

        EXPECT_TRUE(matcher.is_supported_type(object_type::boolean));
        EXPECT_FALSE(matcher.is_supported_type(object_type::float64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::int64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::uint64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::string));
        EXPECT_FALSE(matcher.is_supported_type(object_type::map));
        EXPECT_FALSE(matcher.is_supported_type(object_type::array));
        EXPECT_FALSE(matcher.is_supported_type(object_type::null));
        EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));

        EXPECT_TRUE(matcher.match(owned_object{false}).first);
        EXPECT_FALSE(matcher.match(owned_object{true}).first);
    }

    {
        matcher::equals<bool> matcher(true);

        EXPECT_TRUE(matcher.match(true).first);
        EXPECT_FALSE(matcher.match(false).first);

        EXPECT_TRUE(matcher.is_supported_type(object_type::boolean));
        EXPECT_FALSE(matcher.is_supported_type(object_type::float64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::int64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::uint64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::string));
        EXPECT_FALSE(matcher.is_supported_type(object_type::map));
        EXPECT_FALSE(matcher.is_supported_type(object_type::array));
        EXPECT_FALSE(matcher.is_supported_type(object_type::null));
        EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));

        EXPECT_TRUE(matcher.match(owned_object{true}).first);
        EXPECT_FALSE(matcher.match(owned_object{false}).first);
    }
}

TEST(TestEqualsInt, Basic)
{
    matcher::equals<int64_t> matcher(5);

    EXPECT_TRUE(matcher.match(5).first);
    EXPECT_FALSE(matcher.match(1).first);
    EXPECT_FALSE(matcher.match(-1).first);

    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::float64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_TRUE(matcher.match(owned_object{5L}).first);
    EXPECT_TRUE(matcher.match(owned_object{5L}).first);

    EXPECT_FALSE(matcher.match(owned_object{6L}).first);
    EXPECT_FALSE(matcher.match(owned_object{6L}).first);
}

TEST(TestEqualsUint, Basic)
{
    matcher::equals<uint64_t> matcher(2132132);

    EXPECT_TRUE(matcher.match(2132132).first);
    EXPECT_FALSE(matcher.match(1).first);

    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::float64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_TRUE(matcher.match(owned_object{2132132U}).first);
    EXPECT_TRUE(matcher.match(owned_object{2132132U}).first);

    EXPECT_FALSE(matcher.match(owned_object{6}).first);
    EXPECT_FALSE(matcher.match(owned_object{6}).first);
}

TEST(TestEqualsDouble, Basic)
{
    matcher::equals<double> matcher(5.01, 0.1);

    EXPECT_TRUE(matcher.match(5.01).first);
    EXPECT_FALSE(matcher.match(5.12).first);
    EXPECT_FALSE(matcher.match(-5.1).first);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::int64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_TRUE(matcher.match(owned_object{5.01}).first);
    EXPECT_FALSE(matcher.match(owned_object{5.5}).first);
}

TEST(TestEqualsString, Basic)
{
    matcher::equals<std::string> matcher("aaaa");

    EXPECT_TRUE(matcher.match("aaaa"sv).first);
    EXPECT_TRUE(matcher.match("aaaa"s).first);

    EXPECT_FALSE(matcher.match("aaa"sv).first);
    EXPECT_FALSE(matcher.match("aaa"s).first);

    EXPECT_FALSE(matcher.match("cccc"sv).first);
    EXPECT_FALSE(matcher.match("cccc"s).first);
}

TEST(TestEqualsString, InvalidMatchInput)
{
    matcher::equals<std::string> matcher("aaaa");

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"aaaa", 0}).first);
}

} // namespace
