// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
#include "matcher/greater_than.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestGreaterThanInt, Basic)
{
    matcher::greater_than<int64_t> matcher(5);

    EXPECT_EQ(matcher.match(6).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(5).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(1).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(-1).first, ddwaf::matcher::match_result::match);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_signed(6L)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_unsigned(6UL)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_float(6.0)).first,
        ddwaf::matcher::match_result::match);

    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_signed(5L)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_unsigned(5UL)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_float(5.0)).first,
        ddwaf::matcher::match_result::match);
}

TEST(TestGreaterThanUint, Basic)
{
    matcher::greater_than<uint64_t> matcher(2132132);

    EXPECT_EQ(matcher.match(2132133).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(2132132).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(1).first, ddwaf::matcher::match_result::match);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_signed(2132133L)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_unsigned(2132133UL)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_float(2132133.1)).first,
        ddwaf::matcher::match_result::match);

    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_signed(5L)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_unsigned(5UL)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_float(5.0)).first,
        ddwaf::matcher::match_result::match);
}

TEST(TestGreaterThanDouble, Basic)
{
    matcher::greater_than<double> matcher(5.1);

    EXPECT_EQ(matcher.match(5.11).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(5.1).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(5.09).first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(-5.1).first, ddwaf::matcher::match_result::match);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_signed(6L)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_unsigned(6UL)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match(test::ddwaf_object_da::make_float(5.12)).first,
        ddwaf::matcher::match_result::match);

    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_signed(5L)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_unsigned(5UL)).first,
        ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match(test::ddwaf_object_da::make_float(5.0)).first,
        ddwaf::matcher::match_result::match);
}

// The negated form of greater_than is exposed as the "lower_equal" operator
TEST(TestGreaterThan, Name)
{
    const matcher::greater_than<int64_t> signed_matcher(5);
    EXPECT_STRV(signed_matcher.name(), "greater_than");
    EXPECT_STRV(signed_matcher.negated_name(), "lower_equal");

    const matcher::greater_than<uint64_t> unsigned_matcher(5);
    EXPECT_STRV(unsigned_matcher.name(), "greater_than");
    EXPECT_STRV(unsigned_matcher.negated_name(), "lower_equal");

    const matcher::greater_than<double> float_matcher(5.0);
    EXPECT_STRV(float_matcher.name(), "greater_than");
    EXPECT_STRV(float_matcher.negated_name(), "lower_equal");
}

} // namespace
