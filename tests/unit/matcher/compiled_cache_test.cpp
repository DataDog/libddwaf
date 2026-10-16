// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "configuration/common/parser_exception.hpp"
#include "matcher/compiled_cache.hpp"
#include "matcher/phrase_match.hpp"
#include "matcher/regex_match.hpp"

#include "common/fork_utils.hpp"
#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::matcher;

namespace {

TEST(TestCompiledCache, ReusesLiveEntry)
{
    compiled_cache<int> cache;
    unsigned compilations = 0;
    auto compile = [&]() {
        ++compilations;
        return std::make_shared<int>(42);
    };

    auto first = cache.get_or_compile("key", compile);
    auto second = cache.get_or_compile("key", compile);
    EXPECT_EQ(first.get(), second.get());
    EXPECT_EQ(compilations, 1);
    EXPECT_EQ(cache.size(), 1);

    auto other = cache.get_or_compile("other", compile);
    EXPECT_NE(first.get(), other.get());
    EXPECT_EQ(compilations, 2);
}

TEST(TestCompiledCache, DoesNotRetainExpiredEntry)
{
    compiled_cache<int> cache;
    unsigned compilations = 0;
    auto compile = [&]() {
        ++compilations;
        return std::make_shared<int>(42);
    };

    std::weak_ptr<int> weak = cache.get_or_compile("key", compile);
    EXPECT_TRUE(weak.expired());

    auto obj = cache.get_or_compile("key", compile);
    EXPECT_EQ(compilations, 2);
    EXPECT_EQ(*obj, 42);
}

TEST(TestCompiledCache, FailuresAreNotCached)
{
    compiled_cache<int> cache;
    unsigned compilations = 0;
    auto compile = [&]() {
        ++compilations;
        return std::shared_ptr<int>{};
    };

    EXPECT_EQ(cache.get_or_compile("key", compile), nullptr);
    EXPECT_EQ(cache.get_or_compile("key", compile), nullptr);
    EXPECT_EQ(compilations, 2);
    EXPECT_EQ(cache.size(), 0);
}

TEST(TestCompiledCache, SweepsExpiredEntries)
{
    compiled_cache<int> cache;
    for (int i = 0; i < 1000; ++i) {
        // The result is dropped immediately, so every entry expires
        cache.get_or_compile(std::to_string(i), [i]() { return std::make_shared<int>(i); });
    }
    EXPECT_LT(cache.size(), 100);

    std::vector<std::shared_ptr<int>> live;
    live.reserve(1000);
    for (int i = 0; i < 1000; ++i) {
        live.emplace_back(cache.get_or_compile(
            "live" + std::to_string(i), [i]() { return std::make_shared<int>(i); }));
    }
    EXPECT_GE(cache.size(), 1000);
    for (int i = 0; i < 1000; ++i) {
        auto obj = cache.get_or_compile(
            "live" + std::to_string(i), []() { return std::make_shared<int>(-1); });
        EXPECT_EQ(obj.get(), live[i].get());
    }
}

TEST(TestCompiledCache, ConcurrentCompilationsConverge)
{
    compiled_cache<int> cache;
    std::atomic<unsigned> compilations{0};
    constexpr unsigned nthreads = 8;

    std::vector<std::shared_ptr<int>> results(nthreads);
    std::vector<std::thread> threads;
    threads.reserve(nthreads);
    for (unsigned i = 0; i < nthreads; ++i) {
        threads.emplace_back([&, i]() {
            results[i] = cache.get_or_compile("key", [&]() {
                ++compilations;
                return std::make_shared<int>(42);
            });
        });
    }
    for (auto &t : threads) { t.join(); }

    EXPECT_GE(compilations.load(), 1);
    for (const auto &res : results) {
        ASSERT_NE(res, nullptr);
        EXPECT_EQ(res.get(), results[0].get());
    }
}

TEST(TestCompiledCache, RegexSharedByPatternAndCaseSensitivity)
{
    auto first = compile_regex("^comp[il]+ed_cache$", false);
    auto second = compile_regex("^comp[il]+ed_cache$", false);
    auto sensitive = compile_regex("^comp[il]+ed_cache$", true);
    auto other = compile_regex("^comp[il]+ed_cache_other$", false);

    ASSERT_TRUE(first->ok());
    EXPECT_EQ(first.get(), second.get());
    EXPECT_NE(first.get(), sensitive.get());
    EXPECT_NE(first.get(), other.get());

    EXPECT_FALSE(first->options().case_sensitive());
    EXPECT_TRUE(sensitive->options().case_sensitive());
    EXPECT_EQ(first->options().max_mem(), 512 * 1024);
    EXPECT_FALSE(first->options().log_errors());
}

TEST(TestCompiledCache, InvalidRegexIsNotShared)
{
    auto first = compile_regex("\\uFFFF", true);
    auto second = compile_regex("\\uFFFF", true);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_FALSE(first->ok());
    EXPECT_FALSE(second->ok());
    EXPECT_NE(first.get(), second.get());
    EXPECT_FALSE(first->error_arg().empty());

    EXPECT_THROW(regex_match("\\uFFFF", 0, true), ddwaf::parsing_error);
    EXPECT_THROW(regex_match("\\uFFFF", 0, true), ddwaf::parsing_error);
}

TEST(TestCompiledCache, RegexMatchersWithDifferentOptionsShareProgram)
{
    // min_length isn't part of the program, so both matchers use the same
    // regex but must keep their own minimum length.
    regex_match short_matcher("^ab+$", 0, true);
    regex_match long_matcher("^ab+$", 4, true);

    EXPECT_TRUE(short_matcher.match(std::string_view{"ab"}).first);
    EXPECT_FALSE(long_matcher.match(std::string_view{"ab"}).first);
    EXPECT_TRUE(long_matcher.match(std::string_view{"abbb"}).first);
    EXPECT_STRV(long_matcher.to_string(), "^ab+$");
}

TEST(TestCompiledCache, PhrasesSharedByListAndOrder)
{
    std::vector<const char *> patterns{"alpha", "beta"};
    std::vector<uint32_t> lengths{5, 4};
    std::vector<const char *> reversed{"beta", "alpha"};
    std::vector<uint32_t> reversed_lengths{4, 5};
    // Same bytes, different split
    std::vector<const char *> split{"alphab", "eta"};
    std::vector<uint32_t> split_lengths{6, 3};

    auto first = compile_phrases(patterns, lengths);
    auto second = compile_phrases(patterns, lengths);
    auto third = compile_phrases(reversed, reversed_lengths);
    auto fourth = compile_phrases(split, split_lengths);

    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first.get(), second.get());
    EXPECT_NE(first.get(), third.get());
    EXPECT_NE(first.get(), fourth.get());
}

TEST(TestCompiledCache, PhraseMatchersWithDifferentBoundariesShareAutomaton)
{
    std::vector<const char *> patterns{"string", "other"};
    std::vector<uint32_t> lengths{6, 5};

    phrase_match plain(patterns, lengths, false);
    phrase_match bounded(patterns, lengths, true);

    EXPECT_TRUE(plain.match(std::string_view{"some_stringsss"}).first);
    EXPECT_FALSE(bounded.match(std::string_view{"some_stringsss"}).first);
    EXPECT_TRUE(bounded.match(std::string_view{"some string here"}).first);
}

#ifndef _WIN32
// A child forked while another thread holds the lock of a process-wide cache
// (e.g. while building a ruleset) can still compile regexes and phrases.
TEST(TestCompiledCache, ForkWhileRegexCacheLocked)
{
    EXPECT_TRUE(test::fork_while_locked([] { regex_cache().lock_for_fork(); },
        [] { regex_cache().unlock_after_fork(); },
        [] {
            auto regex = compile_regex("fork_while_locked[0-9]+", true);
            return regex && regex->ok();
        }));
}

TEST(TestCompiledCache, ForkWhilePhraseCacheLocked)
{
    EXPECT_TRUE(test::fork_while_locked([] { phrase_cache().lock_for_fork(); },
        [] { phrase_cache().unlock_after_fork(); },
        [] {
            std::vector<const char *> patterns{"fork_while_locked"};
            std::vector<uint32_t> lengths{17};
            return compile_phrases(patterns, lengths) != nullptr;
        }));
}
#endif

} // namespace
