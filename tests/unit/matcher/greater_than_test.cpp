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

    EXPECT_TRUE(matcher.match(6).first);
    EXPECT_FALSE(matcher.match(5).first);
    EXPECT_FALSE(matcher.match(1).first);
    EXPECT_FALSE(matcher.match(-1).first);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_TRUE(matcher.match(test::ddwaf_object_da::make_signed(6L)).first);
    EXPECT_TRUE(matcher.match(test::ddwaf_object_da::make_unsigned(6UL)).first);
    EXPECT_TRUE(matcher.match(test::ddwaf_object_da::make_float(6.0)).first);

    EXPECT_FALSE(matcher.match(test::ddwaf_object_da::make_signed(5L)).first);
    EXPECT_FALSE(matcher.match(test::ddwaf_object_da::make_unsigned(5UL)).first);
    EXPECT_FALSE(matcher.match(test::ddwaf_object_da::make_float(5.0)).first);
}

TEST(TestGreaterThanUint, Basic)
{
    matcher::greater_than<uint64_t> matcher(2132132);

    EXPECT_TRUE(matcher.match(2132133).first);
    EXPECT_FALSE(matcher.match(2132132).first);
    EXPECT_FALSE(matcher.match(1).first);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_TRUE(matcher.match(test::ddwaf_object_da::make_signed(2132133L)).first);
    EXPECT_TRUE(matcher.match(test::ddwaf_object_da::make_unsigned(2132133UL)).first);
    EXPECT_TRUE(matcher.match(test::ddwaf_object_da::make_float(2132133.1)).first);

    EXPECT_FALSE(matcher.match(test::ddwaf_object_da::make_signed(5L)).first);
    EXPECT_FALSE(matcher.match(test::ddwaf_object_da::make_unsigned(5UL)).first);
    EXPECT_FALSE(matcher.match(test::ddwaf_object_da::make_float(5.0)).first);
}

TEST(TestGreaterThanDouble, Basic)
{
    matcher::greater_than<double> matcher(5.1);

    EXPECT_TRUE(matcher.match(5.11).first);
    EXPECT_FALSE(matcher.match(5.1).first);
    EXPECT_FALSE(matcher.match(5.09).first);
    EXPECT_FALSE(matcher.match(-5.1).first);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_TRUE(matcher.match(test::ddwaf_object_da::make_signed(6L)).first);
    EXPECT_TRUE(matcher.match(test::ddwaf_object_da::make_unsigned(6UL)).first);
    EXPECT_TRUE(matcher.match(test::ddwaf_object_da::make_float(5.12)).first);

    EXPECT_FALSE(matcher.match(test::ddwaf_object_da::make_signed(5L)).first);
    EXPECT_FALSE(matcher.match(test::ddwaf_object_da::make_unsigned(5UL)).first);
    EXPECT_FALSE(matcher.match(test::ddwaf_object_da::make_float(5.0)).first);
}

} // namespace
