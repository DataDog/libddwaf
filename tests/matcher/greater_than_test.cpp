// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "matcher/greater_than.hpp"

using namespace ddwaf;

namespace {

TEST(TestGreaterThanInt, Basic)
{
    matcher::greater_than<int64_t> matcher(5);

    EXPECT_TRUE(matcher.match(6).first);
    EXPECT_FALSE(matcher.match(5).first);
    EXPECT_FALSE(matcher.match(1).first);
    EXPECT_FALSE(matcher.match(-1).first);
}

TEST(TestGreaterThanUint, Basic)
{
    matcher::greater_than<uint64_t> matcher(2132132);

    EXPECT_TRUE(matcher.match(2132133).first);
    EXPECT_FALSE(matcher.match(2132132).first);
    EXPECT_FALSE(matcher.match(1).first);
}

TEST(TestGreaterThanDouble, Basic)
{
    matcher::greater_than<double> matcher(5.1);

    EXPECT_TRUE(matcher.match(5.11).first);
    EXPECT_FALSE(matcher.match(5.1).first);
    EXPECT_FALSE(matcher.match(5.09).first);
    EXPECT_FALSE(matcher.match(-5.1).first);
}

} // namespace
