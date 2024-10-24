// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/regex_match.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf::matcher;

namespace {
TEST(TestRegexMatch, TestBasicCaseInsensitive)
{
    regex_match matcher("^rEgEx$", 0, false);
    EXPECT_STREQ(matcher.to_string().data(), "^rEgEx$");
    EXPECT_STREQ(matcher.name().data(), "match_regex");

    ddwaf_object param;
    ddwaf_object_string(&param, "regex");

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STREQ(highlight.c_str(), "regex");

    ddwaf_object_free(&param);
}

TEST(TestRegexMatch, TestBasicCaseSensitive)
{
    regex_match matcher("^rEgEx$", 0, true);

    ddwaf_object param;
    ddwaf_object_string(&param, "regex");

    EXPECT_FALSE(matcher.match(param).first);

    ddwaf_object param2;
    ddwaf_object_string(&param2, "rEgEx");

    auto [res, highlight] = matcher.match(param2);
    EXPECT_TRUE(res);
    EXPECT_STREQ(highlight.c_str(), "rEgEx");

    ddwaf_object_free(&param);
    ddwaf_object_free(&param2);
}

TEST(TestRegexMatch, TestMinLength)
{
    regex_match matcher("^rEgEx.*$", 6, true);

    ddwaf_object param;
    ddwaf_object param2;
    ddwaf_object_string(&param, "rEgEx");
    ddwaf_object_string(&param2, "rEgExe");

    EXPECT_FALSE(matcher.match(param).first);

    auto [res, highlight] = matcher.match(param2);
    EXPECT_TRUE(res);
    EXPECT_STREQ(highlight.c_str(), "rEgExe");

    ddwaf_object_free(&param);
    ddwaf_object_free(&param2);
}

TEST(TestRegexMatch, TestInvalidInput)
{
    regex_match matcher("^rEgEx.*$", 6, true);

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"*", 0}).first);
}

} // namespace
