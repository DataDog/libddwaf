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

    EXPECT_STR(matcher.name(), "exact_match");
    EXPECT_STR(matcher.to_string(), "");

    {
        std::string_view input{"aaaa"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_EQ(res, ddwaf::matcher::match_result::match);
        EXPECT_STR(highlight, input);
    }

    {
        std::string_view input{"bbbb"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_EQ(res, ddwaf::matcher::match_result::match);
        EXPECT_STR(highlight, input);
    }

    {
        std::string_view input{"cccc"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_EQ(res, ddwaf::matcher::match_result::match);
        EXPECT_STR(highlight, input);
    }

    {
        std::string_view input{"cc"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_NE(res, ddwaf::matcher::match_result::match);
    }

    {
        std::string_view input{"aaaaaa"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_NE(res, ddwaf::matcher::match_result::match);
    }

    {
        std::string_view input{"ddddd"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_NE(res, ddwaf::matcher::match_result::match);
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

    EXPECT_STR(matcher.name(), "exact_match");
    EXPECT_STR(matcher.to_string(), "");

    EXPECT_NE(matcher.match("aaaa").first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match("cccc").first, ddwaf::matcher::match_result::match);

    std::string_view input{"bbbb"};
    auto [res, highlight] = matcher.match(input);
    EXPECT_EQ(res, ddwaf::matcher::match_result::match);
    EXPECT_STR(highlight, input);

    EXPECT_EQ(matcher.match("dddd").first, ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match("eeee").first, ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match("ffff").first, ddwaf::matcher::match_result::match);
}

TEST(TestExactMatch, MultivectorConstructor)
{
    ddwaf::indexed_multivector<std::string, std::pair<std::string, uint64_t>> ivec;
    ivec.emplace("vec1", {{"aaaa", 0}, {"bbbb", 0}, {"cccc", 0}, {"dddd", 0}});
    ivec.emplace("vec2", {{"eeee", 0}, {"ffff", 0}});
    exact_match matcher(ivec);

    EXPECT_STR(matcher.name(), "exact_match");
    EXPECT_STR(matcher.to_string(), "");

    EXPECT_EQ(matcher.match("aaaa").first, ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match("cccc").first, ddwaf::matcher::match_result::match);

    std::string_view input{"bbbb"};
    auto [res, highlight] = matcher.match(input);
    EXPECT_EQ(res, ddwaf::matcher::match_result::match);
    EXPECT_STR(highlight, input);

    EXPECT_EQ(matcher.match("dddd").first, ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match("eeee").first, ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match("ffff").first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match("gggg").first, ddwaf::matcher::match_result::match);
}

TEST(TestExactMatch, MultivectorConstructorExpiration)
{
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
                       .count();

    ddwaf::indexed_multivector<std::string, std::pair<std::string, uint64_t>> ivec;
    ivec.emplace("vec1", {{"aaaa", now - 1}, {"bbbb", now + 100}, {"cccc", now - 1}, {"dddd", 0}});
    ivec.emplace("vec2", {{"dddd", now - 1}, {"eeee", now - 1}});
    ivec.emplace("vec3", {{"eeee", 0}, {"ffff", now + 100}, {"ffff", now}});
    exact_match matcher(ivec);

    EXPECT_STR(matcher.name(), "exact_match");
    EXPECT_STR(matcher.to_string(), "");

    EXPECT_NE(matcher.match("aaaa").first, ddwaf::matcher::match_result::match);
    EXPECT_NE(matcher.match("cccc").first, ddwaf::matcher::match_result::match);

    std::string_view input{"bbbb"};
    auto [res, highlight] = matcher.match(input);
    EXPECT_EQ(res, ddwaf::matcher::match_result::match);
    EXPECT_STR(highlight, input);

    EXPECT_EQ(matcher.match("dddd").first, ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match("eeee").first, ddwaf::matcher::match_result::match);
    EXPECT_EQ(matcher.match("ffff").first, ddwaf::matcher::match_result::match);
}

TEST(TestExactMatch, InvalidMatchInput)
{
    exact_match matcher({"aaaa", "bbbb", "cccc"});

    EXPECT_NE(
        matcher.match(std::string_view{nullptr, 0}).first, ddwaf::matcher::match_result::match);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_NE(
        matcher.match(std::string_view{"aaaa", 0}).first, ddwaf::matcher::match_result::match);
}

} // namespace
