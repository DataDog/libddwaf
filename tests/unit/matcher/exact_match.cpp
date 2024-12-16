// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/exact_match.hpp"

#include <chrono>

#include "common/gtest_utils.hpp"

using namespace ddwaf::matcher;

namespace {

TEST(TestExactMatch, Basic)
{
    exact_match matcher({"aaaa", "bbbb", "cccc"});

    EXPECT_STREQ(matcher.name().data(), "exact_match");
    EXPECT_STREQ(matcher.to_string().data(), "");

    {
        std::string_view input{"aaaa"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_TRUE(res);
        EXPECT_STREQ(highlight.c_str(), input.data());
    }

    {
        std::string_view input{"bbbb"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_TRUE(res);
        EXPECT_STREQ(highlight.c_str(), input.data());
    }

    {
        std::string_view input{"cccc"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_TRUE(res);
        EXPECT_STREQ(highlight.c_str(), input.data());
    }

    {
        std::string_view input{"cc"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_FALSE(res);
    }

    {
        std::string_view input{"aaaaaa"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_FALSE(res);
    }

    {
        std::string_view input{"ddddd"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_FALSE(res);
    }
}

TEST(TestExactMatch, Expiration)
{
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
                       .count();

    exact_match matcher(std::vector<std::pair<std::string, uint64_t>>{{"aaaa", now - 1},
        {"bbbb", now + 100}, {"cccc", now - 1}, {"dddd", 0}, {"dddd", now - 1}, {"eeee", now - 1},
        {"eeee", 0}, {"ffff", now + 100}, {"ffff", now}});

    EXPECT_STREQ(matcher.name().data(), "exact_match");
    EXPECT_STREQ(matcher.to_string().data(), "");

    EXPECT_FALSE(matcher.match("aaaa").first);
    EXPECT_FALSE(matcher.match("cccc").first);

    std::string_view input{"bbbb"};
    auto [res, highlight] = matcher.match(input);
    EXPECT_TRUE(res);
    EXPECT_STREQ(highlight.c_str(), input.data());

    EXPECT_TRUE(matcher.match("dddd").first);
    EXPECT_TRUE(matcher.match("eeee").first);
    EXPECT_TRUE(matcher.match("ffff").first);
}

TEST(TestExactMatch, InvalidMatchInput)
{
    exact_match matcher({"aaaa", "bbbb", "cccc"});

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"aaaa", 0}).first);
}

} // namespace
