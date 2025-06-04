// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/regex_match.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::matcher;

namespace {
TEST(TestRegexMatch, TestBasicCaseInsensitive)
{
    regex_match matcher("^rEgEx$", 0, false);
    EXPECT_STRV(matcher.to_string(), "^rEgEx$");
    EXPECT_STRV(matcher.name(), "match_regex");

    owned_object param{"regex"};

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "regex");
}

TEST(TestRegexMatch, TestBasicCaseSensitive)
{
    regex_match matcher("^rEgEx$", 0, true);

    owned_object param{"regex"};

    EXPECT_FALSE(matcher.match(param).first);

    owned_object param2{"rEgEx"};

    auto [res, highlight] = matcher.match(param2);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "rEgEx");
}

TEST(TestRegexMatch, TestMinLength)
{
    regex_match matcher("^rEgEx.*$", 6, true);

    owned_object param{"rEgEx"};
    owned_object param2{"rEgExe"};

    EXPECT_FALSE(matcher.match(param).first);

    auto [res, highlight] = matcher.match(param2);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "rEgExe");
}

TEST(TestRegexMatch, TestInvalidInput)
{
    regex_match matcher("^rEgEx.*$", 6, true);

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"*", 0}).first);
}

} // namespace
