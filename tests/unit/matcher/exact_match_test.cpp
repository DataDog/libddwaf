// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/exact_match.hpp"

#include <chrono>
#include <unordered_set>

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
        EXPECT_TRUE(res);
        EXPECT_STR(highlight, input);
    }

    {
        std::string_view input{"bbbb"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_TRUE(res);
        EXPECT_STR(highlight, input);
    }

    {
        std::string_view input{"cccc"};
        auto [res, highlight] = matcher.match(input);
        EXPECT_TRUE(res);
        EXPECT_STR(highlight, input);
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

    EXPECT_STR(matcher.name(), "exact_match");
    EXPECT_STR(matcher.to_string(), "");

    EXPECT_FALSE(matcher.match("aaaa").first);
    EXPECT_FALSE(matcher.match("cccc").first);

    std::string_view input{"bbbb"};
    auto [res, highlight] = matcher.match(input);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, input);

    EXPECT_TRUE(matcher.match("dddd").first);
    EXPECT_TRUE(matcher.match("eeee").first);
    EXPECT_TRUE(matcher.match("ffff").first);
}

TEST(TestExactMatch, MultivectorConstructor)
{
    ddwaf::indexed_multivector<std::string, std::pair<std::string, uint64_t>> ivec;
    ivec.emplace("vec1", {{"aaaa", 0}, {"bbbb", 0}, {"cccc", 0}, {"dddd", 0}});
    ivec.emplace("vec2", {{"eeee", 0}, {"ffff", 0}});
    exact_match matcher(ivec);

    EXPECT_STR(matcher.name(), "exact_match");
    EXPECT_STR(matcher.to_string(), "");

    EXPECT_TRUE(matcher.match("aaaa").first);
    EXPECT_TRUE(matcher.match("cccc").first);

    std::string_view input{"bbbb"};
    auto [res, highlight] = matcher.match(input);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, input);

    EXPECT_TRUE(matcher.match("dddd").first);
    EXPECT_TRUE(matcher.match("eeee").first);
    EXPECT_TRUE(matcher.match("ffff").first);
    EXPECT_FALSE(matcher.match("gggg").first);
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

    EXPECT_FALSE(matcher.match("aaaa").first);
    EXPECT_FALSE(matcher.match("cccc").first);

    std::string_view input{"bbbb"};
    auto [res, highlight] = matcher.match(input);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, input);

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

TEST(TestExactMatch, ExpiringStringListConstructor)
{
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
                       .count();

    ddwaf::indexed_multivector<std::string, ddwaf::expiring_string_list::value_type,
        ddwaf::expiring_string_list>
        ivec;
    ivec.emplace("vec1", {{"aaaa", now - 1}, {"bbbb", now + 100}, {"cccc", now - 1}, {"dddd", 0}});
    ivec.emplace("empty", {});
    ivec.emplace("vec2", {{"dddd", now - 1}, {"eeee", now - 1}, {"", 0}});
    ivec.emplace("vec3", {{"eeee", 0}, {"ffff", now + 100}, {"ffff", now - 5}});
    exact_match matcher(ivec);

    EXPECT_FALSE(matcher.match("aaaa").first);
    EXPECT_FALSE(matcher.match("cccc").first);
    EXPECT_FALSE(matcher.match("").first);
    EXPECT_FALSE(matcher.match("aaa").first);
    EXPECT_FALSE(matcher.match("aaaaa").first);
    EXPECT_FALSE(matcher.match(std::string(1000, 'a')).first);

    auto [res, highlight] = matcher.match(std::string_view{"bbbb"});
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "bbbb");

    EXPECT_TRUE(matcher.match("dddd").first);
    EXPECT_TRUE(matcher.match("eeee").first);
    EXPECT_TRUE(matcher.match("ffff").first);
}

TEST(TestExactMatch, EmptyData)
{
    exact_match matcher(std::vector<std::string>{});
    EXPECT_FALSE(matcher.match("aaaa").first);
    EXPECT_FALSE(matcher.match("").first);

    exact_match default_matcher;
    EXPECT_FALSE(default_matcher.match("aaaa").first);
}

TEST(TestExactMatch, ManyValues)
{
    // Exercise collisions and probing with many values of varying lengths,
    // including duplicates, against a reference set.
    std::vector<std::string> values;
    std::unordered_set<std::string> reference;
    uint64_t state = 0x12345678;
    for (unsigned i = 0; i < 20000; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        std::string value = std::to_string(state >> (state % 48));
        value.append(state % 17, static_cast<char>('a' + (i % 26)));
        reference.emplace(value);
        values.emplace_back(value);
        if (i % 7 == 0) {
            values.emplace_back(value);
        }
    }

    exact_match matcher(std::vector<std::string>{values});
    for (const auto &value : reference) { EXPECT_TRUE(matcher.match(value).first) << value; }

    for (const auto &value : values) {
        auto copy = value + "x";
        EXPECT_EQ(matcher.match(copy).first, reference.contains(copy)) << copy;
        copy = value.substr(1);
        EXPECT_EQ(matcher.match(copy).first, reference.contains(copy)) << copy;
    }

    // Copies are independent of the original
    exact_match copy{matcher};
    matcher = exact_match{};
    for (const auto &value : reference) { EXPECT_TRUE(copy.match(value).first) << value; }
}

} // namespace
