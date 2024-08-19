// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "matcher/lower_than.hpp"

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
}

TEST(TestlowerThanUint, Basic)
{
    matcher::lower_than<uint64_t> matcher(2132132);

    EXPECT_TRUE(matcher.match(2132131).first);
    EXPECT_FALSE(matcher.match(2132133).first);
    EXPECT_FALSE(matcher.match(2132132).first);
}

TEST(TestlowerThanDouble, Basic)
{
    matcher::lower_than<double> matcher(5.1);

    EXPECT_TRUE(matcher.match(5.09).first);
    EXPECT_TRUE(matcher.match(-5.1).first);
    EXPECT_FALSE(matcher.match(5.1).first);
    EXPECT_FALSE(matcher.match(5.2).first);
}

} // namespace
