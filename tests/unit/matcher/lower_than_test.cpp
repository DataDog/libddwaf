// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/lower_than.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestlowerThanInt, Basic)
{
    matcher::lower_than<int64_t> matcher(5);

    EXPECT_TRUE(matcher.match(-1).first);
    EXPECT_TRUE(matcher.match(4).first);
    EXPECT_FALSE(matcher.match(6).first);
    EXPECT_FALSE(matcher.match(5).first);
    EXPECT_FALSE(matcher.match(99).first);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_TRUE(matcher.match(owned_object{4L}).first);
    EXPECT_TRUE(matcher.match(owned_object{4UL}).first);
    EXPECT_TRUE(matcher.match(owned_object{4.0}).first);

    EXPECT_FALSE(matcher.match(owned_object{5L}).first);
    EXPECT_FALSE(matcher.match(owned_object{5UL}).first);
    EXPECT_FALSE(matcher.match(owned_object{5.0}).first);
}

TEST(TestlowerThanUint, Basic)
{
    matcher::lower_than<uint64_t> matcher(2132132);

    EXPECT_TRUE(matcher.match(2132131).first);
    EXPECT_FALSE(matcher.match(2132133).first);
    EXPECT_FALSE(matcher.match(2132132).first);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_TRUE(matcher.match(owned_object{2132131L}).first);
    EXPECT_TRUE(matcher.match(owned_object{2132131UL}).first);
    EXPECT_TRUE(matcher.match(owned_object{2132131.9}).first);

    EXPECT_FALSE(matcher.match(owned_object{2132133L}).first);
    EXPECT_FALSE(matcher.match(owned_object{2132133UL}).first);
    EXPECT_FALSE(matcher.match(owned_object{2132132.1}).first);
}

TEST(TestlowerThanDouble, Basic)
{
    matcher::lower_than<double> matcher(5.1);

    EXPECT_TRUE(matcher.match(5.09).first);
    EXPECT_TRUE(matcher.match(-5.1).first);
    EXPECT_FALSE(matcher.match(5.1).first);
    EXPECT_FALSE(matcher.match(5.2).first);

    EXPECT_TRUE(matcher.is_supported_type(object_type::float64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::int64));
    EXPECT_TRUE(matcher.is_supported_type(object_type::uint64));
    EXPECT_FALSE(matcher.is_supported_type(object_type::string));
    EXPECT_FALSE(matcher.is_supported_type(object_type::map));
    EXPECT_FALSE(matcher.is_supported_type(object_type::array));
    EXPECT_FALSE(matcher.is_supported_type(object_type::null));
    EXPECT_FALSE(matcher.is_supported_type(object_type::invalid));
    EXPECT_FALSE(matcher.is_supported_type(object_type::boolean));

    EXPECT_TRUE(matcher.match(owned_object{5L}).first);
    EXPECT_TRUE(matcher.match(owned_object{5UL}).first);
    EXPECT_TRUE(matcher.match(owned_object{5.09}).first);

    EXPECT_FALSE(matcher.match(owned_object{6L}).first);
    EXPECT_FALSE(matcher.match(owned_object{6UL}).first);
    EXPECT_FALSE(matcher.match(owned_object{6.0}).first);
}

} // namespace
