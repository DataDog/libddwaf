// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "matcher/equals.hpp"

#include <algorithm>

TEST(TestEqualsBool, Basic)
{
    {
        matcher::equals<bool> matcher(false);

        EXPECT_TRUE(matcher.match(false).first);
        EXPECT_FALSE(matcher.match(true).first);
    }

    {
        matcher::equals<bool> matcher(true);

        EXPECT_TRUE(matcher.match(true).first);
        EXPECT_FALSE(matcher.match(false).first);
    }
}

TEST(TestEqualsInt, Basic)
{
    matcher::equals<int64_t> matcher(5);

    EXPECT_TRUE(matcher.match(5).first);
    EXPECT_FALSE(matcher.match(1).first);
    EXPECT_FALSE(matcher.match(-1).first);
}

TEST(TestEqualsUint, Basic)
{
    matcher::equals<uint64_t> matcher(2132132);

    EXPECT_TRUE(matcher.match(2132132).first);
    EXPECT_FALSE(matcher.match(1).first);
}

TEST(TestEqualsDouble, Basic)
{
    matcher::equals<double> matcher(5.1, 0.0001);

    EXPECT_TRUE(matcher.match(5.1).first);
    EXPECT_FALSE(matcher.match(5.11).first);
    EXPECT_FALSE(matcher.match(-5.1).first);
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
    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 30}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"aaaa", 0}).first);
}
