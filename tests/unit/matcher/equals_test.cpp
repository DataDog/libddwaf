// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/equals.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

TEST(TestEqualsBool, Basic)
{
    {
        matcher::equals<bool> matcher(false);

        EXPECT_EQ(matcher.match(false).first, ddwaf::matcher::match_result::match);
        EXPECT_NE(matcher.match(true).first, ddwaf::matcher::match_result::match);

        EXPECT_TRUE(matcher.is_supported_type(object_type::boolean));
        EXPECT_FALSE(matcher.is_supported_type(object_type::float64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::int64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::uint64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::string));
        EXPECT_FALSE(matcher.is_supported_type(object_type::map));
        EXPECT_FALSE(matcher.is_supported_type(object_type::array));
        EXPECT_FALSE(matcher.is_supported_type(object_type::null));
        EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));

        EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_boolean(false)).first,
            ddwaf::matcher::match_result::match);
        EXPECT_NE(matcher.match(test::ddwaf_object_da::make_boolean(true)).first,
            ddwaf::matcher::match_result::match);
    }

    {
        matcher::equals<bool> matcher(true);

        EXPECT_EQ(matcher.match(true).first, ddwaf::matcher::match_result::match);
        EXPECT_NE(matcher.match(false).first, ddwaf::matcher::match_result::match);

        EXPECT_TRUE(matcher.is_supported_type(object_type::boolean));
        EXPECT_FALSE(matcher.is_supported_type(object_type::float64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::int64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::uint64));
        EXPECT_FALSE(matcher.is_supported_type(object_type::string));
        EXPECT_FALSE(matcher.is_supported_type(object_type::map));
        EXPECT_FALSE(matcher.is_supported_type(object_type::array));
        EXPECT_FALSE(matcher.is_supported_type(object_type::null));
        EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));

        EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_boolean(true)).first,
            ddwaf::matcher::match_result::match);
        EXPECT_NE(matcher.match(test::ddwaf_object_da::make_boolean(false)).first,
            ddwaf::matcher::match_result::match);
    }
}

TEST(TestEqualsInt, Basic)
{
    matcher::equals<int64_t> matcher(5);

    EXPECT_EQ(matcher.match(5).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(1).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(-1).first, ddwaf::matcher::match_result::match);

    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::float64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_signed(5L)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_signed(5L)).first,
        ddwaf::matcher::match_result::match);

    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_signed(6L)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_signed(6L)).first,
        ddwaf::matcher::match_result::match);
}

TEST(TestEqualsUint, Basic)
{
    matcher::equals<uint64_t> matcher(2132132);

    EXPECT_EQ(matcher.match(2132132).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(1).first, ddwaf::matcher::match_result::match);

    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::float64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_unsigned(2132132U)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_unsigned(2132132U)).first,
        ddwaf::matcher::match_result::match);

    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_signed(6)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_signed(6)).first,
        ddwaf::matcher::match_result::match);
}

TEST(TestEqualsDouble, Basic)
{
    matcher::equals<double> matcher(5.01, 0.1);

    EXPECT_EQ(matcher.match(5.01).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(5.12).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(-5.1).first, ddwaf::matcher::match_result::match);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::int64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_float(5.01)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_float(5.5)).first,
        ddwaf::matcher::match_result::match);
}

TEST(TestEqualsString, Basic)
{
    matcher::equals<std::string> matcher("aaaa");

    EXPECT_EQ(matcher.match("aaaa"sv).first, ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match("aaaa"s).first, ddwaf::matcher::match_result::match);

    EXPECT_NE(matcher.match("aaa"sv).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match("aaa"s).first, ddwaf::matcher::match_result::match);

    EXPECT_NE(matcher.match("cccc"sv).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match("cccc"s).first, ddwaf::matcher::match_result::match);
}

TEST(TestEqualsString, InvalidMatchInput)
{
    matcher::equals<std::string> matcher("aaaa");

    EXPECT_NE(
        matcher.match(std::string_view{nullptr, 0}).first, ddwaf::matcher::match_result::match);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_NE(
        matcher.match(std::string_view{"aaaa", 0}).first, ddwaf::matcher::match_result::match);
}

TEST(TestEqualsConvertStrings, Bool)
{
    matcher::equals<bool, true> matcher(true);

    EXPECT_TRUE(matcher.is_supported_type(object_type::string));
    EXPECT_TRUE(matcher.is_supported_type(object_type::boolean));

    EXPECT_EQ(matcher.match(std::string_view{"true"}).first, matcher::match_result::match);
    EXPECT_EQ(matcher.match(std::string_view{"TrUe"}).first, matcher::match_result::match);
    EXPECT_EQ(matcher.match(std::string_view{"false"}).first, matcher::match_result::no_match);
    EXPECT_EQ(matcher.match(std::string_view{"yes"}).first, matcher::match_result::unknown);

    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_string_literal("true")).first,
        matcher::match_result::match);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_string_literal("1")).first,
        matcher::match_result::unknown);
}

TEST(TestEqualsConvertStrings, Signed)
{
    matcher::equals<int64_t, true> matcher(-5);

    EXPECT_TRUE(matcher.is_supported_type(object_type::string));

    EXPECT_EQ(matcher.match(std::string_view{"-5"}).first, matcher::match_result::match);
    EXPECT_EQ(matcher.match(std::string_view{"5"}).first, matcher::match_result::no_match);
    EXPECT_EQ(matcher.match(std::string_view{"-5.0"}).first, matcher::match_result::unknown);
    EXPECT_EQ(matcher.match(std::string_view{"-5a"}).first, matcher::match_result::unknown);
    EXPECT_EQ(
        matcher.match(test::ddwaf_object_da::make_signed(-5)).first, matcher::match_result::match);
}

TEST(TestEqualsConvertStrings, Double)
{
    matcher::equals<double, true> matcher(2.5, 0.01);

    EXPECT_TRUE(matcher.is_supported_type(object_type::string));

    EXPECT_EQ(matcher.match(std::string_view{"2.5"}).first, matcher::match_result::match);
    EXPECT_EQ(matcher.match(std::string_view{"2.6"}).first, matcher::match_result::no_match);
    EXPECT_EQ(matcher.match(std::string_view{"abc"}).first, matcher::match_result::unknown);
}

TEST(TestEqualsConvertStrings, DisabledByDefault)
{
    matcher::equals<int64_t> matcher(5);

    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_EQ(matcher.match(std::string_view{"5"}).first, matcher::match_result::unknown);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_string_literal("5")).first,
        matcher::match_result::unknown);
}

} // namespace
