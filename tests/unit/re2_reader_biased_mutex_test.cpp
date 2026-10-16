// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "re2/re2.h"
#include "re2/util/reader_biased_mutex.h"

#include "common/gtest_utils.hpp"

using re2::ReaderBiasedMutex;

namespace {

TEST(TestReaderBiasedMutex, ReadersTakeTheFastPathWhileBiased)
{
    ReaderBiasedMutex mu;
    auto *token = mu.ReaderLock();
    EXPECT_NE(token, nullptr);
    mu.ReaderUnlock(token);

    // The slot was released, so the next read is fast again
    token = mu.ReaderLock();
    EXPECT_NE(token, nullptr);
    mu.ReaderUnlock(token);
}

TEST(TestReaderBiasedMutex, WriterRevokesBiasAndNextReaderRestoresIt)
{
    ReaderBiasedMutex mu;
    mu.WriterLock();
    mu.WriterUnlock();

    // The first reader after a writer goes through the underlying mutex...
    auto *token = mu.ReaderLock();
    EXPECT_EQ(token, nullptr);
    mu.ReaderUnlock(token);

    // ... and restores the bias for the following ones
    token = mu.ReaderLock();
    EXPECT_NE(token, nullptr);
    mu.ReaderUnlock(token);
}

TEST(TestReaderBiasedMutex, NestedReadersOfDifferentMutexes)
{
    // A thread has a single slot, so the inner read lock falls back to the
    // underlying mutex; both must still be held and released correctly.
    ReaderBiasedMutex outer;
    ReaderBiasedMutex inner;

    auto *outer_token = outer.ReaderLock();
    EXPECT_NE(outer_token, nullptr);
    auto *inner_token = inner.ReaderLock();
    EXPECT_EQ(inner_token, nullptr);
    inner.ReaderUnlock(inner_token);
    outer.ReaderUnlock(outer_token);

    // Both can be written now, i.e. no reader is left behind
    outer.WriterLock();
    outer.WriterUnlock();
    inner.WriterLock();
    inner.WriterUnlock();
}

TEST(TestReaderBiasedMutex, ReaderAndWriterOnAnotherMutexDoNotInterfere)
{
    ReaderBiasedMutex read_mu;
    ReaderBiasedMutex write_mu;

    auto *token = read_mu.ReaderLock();
    EXPECT_NE(token, nullptr);

    // A writer of another mutex must not wait for this thread's slot
    std::thread writer{[&] {
        write_mu.WriterLock();
        write_mu.WriterUnlock();
    }};
    writer.join();

    read_mu.ReaderUnlock(token);
}

TEST(TestReaderBiasedMutex, WriterWaitsForFastPathReader)
{
    ReaderBiasedMutex mu;
    std::atomic<bool> reader_locked{false};
    std::atomic<bool> release_reader{false};
    std::atomic<bool> writer_locked{false};

    std::thread reader{[&] {
        auto *token = mu.ReaderLock();
        EXPECT_NE(token, nullptr);
        reader_locked.store(true);
        while (!release_reader.load()) { std::this_thread::yield(); }
        // The writer cannot have entered while the read lock is held
        EXPECT_FALSE(writer_locked.load());
        mu.ReaderUnlock(token);
    }};

    while (!reader_locked.load()) { std::this_thread::yield(); }

    std::thread writer{[&] {
        mu.WriterLock();
        writer_locked.store(true);
        mu.WriterUnlock();
    }};

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(writer_locked.load());
    release_reader.store(true);

    reader.join();
    writer.join();
    EXPECT_TRUE(writer_locked.load());
}

TEST(TestReaderBiasedMutex, ReaderWaitsForWriter)
{
    ReaderBiasedMutex mu;
    std::atomic<bool> reader_locked{false};

    mu.WriterLock();
    std::thread reader{[&] {
        auto *token = mu.ReaderLock();
        reader_locked.store(true);
        mu.ReaderUnlock(token);
    }};

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(reader_locked.load());
    mu.WriterUnlock();

    reader.join();
    EXPECT_TRUE(reader_locked.load());
}

TEST(TestReaderBiasedMutex, ConcurrentReadersAndWriters)
{
    // Writers keep two plain (non-atomic) counters equal; readers must never
    // see them differ. The data is deliberately not atomic so that a broken
    // exclusion is also caught by ThreadSanitizer.
    struct shared_data {
        uint64_t first{0};
        uint64_t second{0};
    };

    constexpr unsigned num_readers = 8;
    constexpr unsigned num_writers = 2;
    constexpr unsigned writes_per_writer = 2000;
    constexpr unsigned reads_per_reader = 20000;

    ReaderBiasedMutex mu;
    auto data = std::make_unique<shared_data>();
    std::atomic<unsigned> inconsistent{0};
    std::atomic<unsigned> fast_reads{0};

    std::vector<std::thread> threads;
    threads.reserve(num_readers + num_writers);
    for (unsigned i = 0; i < num_readers; ++i) {
        threads.emplace_back([&] {
            unsigned fast = 0;
            for (unsigned j = 0; j < reads_per_reader; ++j) {
                auto *token = mu.ReaderLock();
                fast += token != nullptr ? 1 : 0;
                if (data->first != data->second) {
                    inconsistent.fetch_add(1, std::memory_order_relaxed);
                }
                mu.ReaderUnlock(token);
            }
            fast_reads.fetch_add(fast, std::memory_order_relaxed);
        });
    }
    for (unsigned i = 0; i < num_writers; ++i) {
        threads.emplace_back([&] {
            for (unsigned j = 0; j < writes_per_writer; ++j) {
                mu.WriterLock();
                ++data->first;
                std::this_thread::yield();
                ++data->second;
                mu.WriterUnlock();
            }
        });
    }
    for (auto &t : threads) { t.join(); }

    EXPECT_EQ(inconsistent.load(), 0);
    EXPECT_EQ(data->first, num_writers * writes_per_writer);
    EXPECT_EQ(data->second, num_writers * writes_per_writer);
    // Not a correctness requirement, but the bias must be restored after
    // writers, or the fast path would be lost for good.
    EXPECT_GT(fast_reads.load(), 0);
}

// The DFA state cache is the user of ReaderBiasedMutex: searches read it
// concurrently, and a search that fills it resets it under the write lock.
// A small memory budget and a pattern with exponentially many DFA states make
// the cache resets frequent while other threads keep searching.
std::atomic<unsigned> dfa_cache_resets{0};
void count_dfa_cache_reset(const re2::hooks::DFAStateCacheReset & /*unused*/)
{
    dfa_cache_resets.fetch_add(1, std::memory_order_relaxed);
}

TEST(TestReaderBiasedMutex, ConcurrentRegexSearchesWithCacheResets)
{
    constexpr std::string_view pattern = "a[ab]{12}c";
    constexpr unsigned num_threads = 8;
    constexpr unsigned num_texts = 64;
    constexpr unsigned searches_per_thread = 256;
    constexpr std::size_t text_size = 4096;

    std::mt19937 rng{42}; // NOLINT(cert-msc32-c,cert-msc51-cpp)
    std::vector<std::string> texts;
    texts.reserve(num_texts);
    for (unsigned i = 0; i < num_texts; ++i) {
        std::string text(text_size, 'a');
        for (auto &c : text) { c = (rng() & 1) != 0 ? 'a' : 'b'; }
        // Every other text gets a 'c', so some match and some do not
        if (i % 2 == 0) { text[rng() % text_size] = 'c'; }
        texts.emplace_back(std::move(text));
    }

    auto search = [](const re2::RE2 &regex, std::string_view text) -> std::string_view {
        std::string_view match;
        if (!regex.Match(text, 0, text.size(), re2::RE2::UNANCHORED, &match, 1)) {
            return {};
        }
        return match;
    };

    // Reference results, from a regex with the default memory budget
    std::vector<std::string_view> expected;
    {
        const re2::RE2 reference{pattern};
        ASSERT_TRUE(reference.ok());
        expected.reserve(num_texts);
        for (const auto &text : texts) { expected.emplace_back(search(reference, text)); }
    }

    re2::RE2::Options options;
    options.set_max_mem(64 * 1024);
    const re2::RE2 regex{pattern, options};
    ASSERT_TRUE(regex.ok());

    dfa_cache_resets.store(0);
    auto *previous_hook = re2::hooks::GetDFAStateCacheResetHook();
    re2::hooks::SetDFAStateCacheResetHook(count_dfa_cache_reset);

    std::atomic<unsigned> mismatches{0};
    std::vector<std::thread> threads;
    threads.reserve(num_threads);
    for (unsigned t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t] {
            for (unsigned j = 0; j < searches_per_thread; ++j) {
                auto idx = (t * 7 + j) % num_texts;
                if (search(regex, texts[idx]) != expected[idx]) {
                    mismatches.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto &t : threads) { t.join(); }

    re2::hooks::SetDFAStateCacheResetHook(previous_hook);

    EXPECT_EQ(mismatches.load(), 0);
    // Otherwise the test did not exercise the write side
    EXPECT_GT(dfa_cache_resets.load(), 0);
}

} // namespace
