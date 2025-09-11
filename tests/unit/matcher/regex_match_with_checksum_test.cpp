// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "checksum/luhn_checksum.hpp"
#include "matcher/regex_match_with_checksum.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf::matcher;

namespace {
TEST(TestRegexMatchWithChecksum, Match)
{
    regex_match_with_checksum matcher(
        R"(\b4\d{3}(?:(?:,\d{4}){3}|(?:\s\d{4}){3}|(?:\.\d{4}){3}|(?:-\d{4}){3})\b)", 16, true,
        std::make_unique<ddwaf::luhn_checksum>());

    auto [res, highlight] = matcher.match("4000-0000-0000-1000");
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "4000-0000-0000-1000");
}

TEST(TestRegexMatchWithChecksum, MatchRegexButNotChecksum)
{
    regex_match_with_checksum matcher(
        R"(\b4\d{3}(?:(?:,\d{4}){3}|(?:\s\d{4}){3}|(?:\.\d{4}){3}|(?:-\d{4}){3})\b)", 16, true,
        std::make_unique<ddwaf::luhn_checksum>());

    auto [res, highlight] = matcher.match("4000-0000-0000-0000");
    EXPECT_FALSE(res);
}

TEST(TestRegexMatchWithChecksum, NoMatch)
{
    regex_match_with_checksum matcher(
        R"(\b4\d{3}(?:(?:,\d{4}){3}|(?:\s\d{4}){3}|(?:\.\d{4}){3}|(?:-\d{4}){3})\b)", 16, true,
        std::make_unique<ddwaf::luhn_checksum>());

    auto [res, highlight] = matcher.match("whatisthis");
    EXPECT_FALSE(res);
}

TEST(TestRegexMatchWithChecksum, MinLength)
{
    regex_match_with_checksum matcher(
        R"(\b4\d{3}(?:(?:,\d{4}){3}|(?:\s\d{4}){3}|(?:\.\d{4}){3}|(?:-\d{4}){3})\b)", 20, true,
        std::make_unique<ddwaf::luhn_checksum>());

    auto [res, highlight] = matcher.match("4000-0000-0000-1000");
    EXPECT_FALSE(res);
}

} // namespace
