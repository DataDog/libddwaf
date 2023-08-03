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
        matcher::equals<bool> processor(false);

        EXPECT_TRUE(processor.match(false).first);
        EXPECT_FALSE(processor.match(true).first);
    }

    {
        matcher::equals<bool> processor(true);

        EXPECT_TRUE(processor.match(true).first);
        EXPECT_FALSE(processor.match(false).first);
    }
}

TEST(TestEqualsInt, Basic)
{
    matcher::equals<int64_t> processor(5);

    EXPECT_TRUE(processor.match(5).first);
    EXPECT_FALSE(processor.match(1).first);
    EXPECT_FALSE(processor.match(-1).first);
}

TEST(TestEqualsUint, Basic)
{
    matcher::equals<uint64_t> processor(2132132);

    EXPECT_TRUE(processor.match(2132132).first);
    EXPECT_FALSE(processor.match(1).first);
}

TEST(TestEqualsString, Basic)
{
    matcher::equals<std::string> processor("aaaa");

    EXPECT_TRUE(processor.match("aaaa"sv).first);
    EXPECT_TRUE(processor.match("aaaa"s).first);

    EXPECT_FALSE(processor.match("aaa"sv).first);
    EXPECT_FALSE(processor.match("aaa"s).first);

    EXPECT_FALSE(processor.match("cccc"sv).first);
    EXPECT_FALSE(processor.match("cccc"s).first);
}

TEST(TestEqualsString, InvalidMatchInput)
{
    matcher::equals<std::string> processor("aaaa");

    EXPECT_FALSE(processor.match(std::string_view{nullptr, 0}).first);
    EXPECT_FALSE(processor.match(std::string_view{nullptr, 30}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(processor.match(std::string_view{"aaaa", 0}).first);
}
