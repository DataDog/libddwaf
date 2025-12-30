// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "configuration/common/parser_exception.hpp"
#include "matcher/regex_match.hpp"

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::matcher;

namespace {

TEST(TestRegexMatch, InvalidRegex)
{
    EXPECT_THROW(regex_match("\\uFFFF", 16, true), ddwaf::parsing_error);
}
TEST(TestRegexMatch, TestBasicCaseInsensitive)
{
    regex_match matcher("^rEgEx$", 0, false);
    EXPECT_STRV(matcher.to_string(), "^rEgEx$");
    EXPECT_STRV(matcher.name(), "match_regex");

    owned_object param = test::ddwaf_object_da::make_string("regex");

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "regex");
}

TEST(TestRegexMatch, TestBasicCaseSensitive)
{
    regex_match matcher("^rEgEx$", 0, true);

    owned_object param = test::ddwaf_object_da::make_string("regex");

    EXPECT_FALSE(matcher.match(param).first);

    owned_object param2 = test::ddwaf_object_da::make_string("rEgEx");

    auto [res, highlight] = matcher.match(param2);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "rEgEx");
}

TEST(TestRegexMatch, TestMinLength)
{
    regex_match matcher("^rEgEx.*$", 6, true);

    owned_object param = test::ddwaf_object_da::make_string("rEgEx");
    owned_object param2 = test::ddwaf_object_da::make_string("rEgExe");

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
