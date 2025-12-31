// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/hidden_ascii_match.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

TEST(TestHiddenAscii, Basic)
{
    matcher::hidden_ascii_match matcher;
    EXPECT_STR(matcher.to_string(), "");
    EXPECT_STR(matcher.name(), "hidden_ascii_match");
}

TEST(TestHiddenAscii, CompleteMatch)
{
    matcher::hidden_ascii_match matcher;

    std::string input =
        "\xF3\xA0\x81\xB4\xF3\xA0\x81\xA8\xF3\xA0\x81\xA9\xF3\xA0\x81\xB3 "
        "\xF3\xA0\x81\xA9\xF3\xA0\x81\xB3 "
        "\xF3\xA0\x81\xA8\xF3\xA0\x81\xA9\xF3\xA0\x81\xA4\xF3\xA0\x81\xA4\xF3\xA0\x81\xA5\xF3\xA0"
        "\x81\xAE \xF3\xA0\x81\xA1\xF3\xA0\x81\xB3\xF3\xA0\x81\xA3\xF3\xA0\x81\xA9\xF3\xA0\x81\xA9";
    auto [res, highlight] = matcher.match(input);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "this is hidden ascii");
}

TEST(TestHiddenAscii, NoMatch)
{
    matcher::hidden_ascii_match matcher;

    std::string input = "this is perfectly normal text";
    auto [res, highlight] = matcher.match(input);
    EXPECT_FALSE(res);
    EXPECT_STR(highlight, "");
}

TEST(TestHiddenAscii, InlineMatch)
{
    matcher::hidden_ascii_match matcher;

    std::string input = "t\xF3\xA0\x81\xA8\xF3\xA0\x81\xA9\xF3\xA0\x81\xB3 is "
                        "\xF3\xA0\x81\xA8\xF3\xA0\x81\xA9\xF3\xA0\x81\xA4\xF3\xA0\x81\xA4\xF3\xA0"
                        "\x81\xA5\xF3\xA0\x81\xAE asci\xF3\xA0\x81\xA9";
    auto [res, highlight] = matcher.match(input);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "this is hidden ascii");
}
} // namespace
