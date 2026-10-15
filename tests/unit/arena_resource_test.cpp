// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "arena_resource.hpp"
#include "sanitizer.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::memory;

namespace {

namespace cache = arena_block_cache;

bool is_aligned(void *ptr, std::size_t alignment)
{
    return (reinterpret_cast<std::uintptr_t>(ptr) & (alignment - 1)) == 0;
}

class TestArenaResource : public ::testing::Test {
public:
    void SetUp() override { cache::trim(); }
    void TearDown() override { cache::trim(); }
};

TEST_F(TestArenaResource, AcquireRoundsUpToClass)
{
    std::size_t size = 1;
    void *block = cache::acquire(size);
    EXPECT_EQ(size, cache::min_block_size);
    cache::release(block, size);

    size = cache::min_block_size + 1;
    block = cache::acquire(size);
    EXPECT_EQ(size, cache::min_block_size * 2);
    cache::release(block, size);

    size = cache::max_block_size;
    block = cache::acquire(size);
    EXPECT_EQ(size, cache::max_block_size);
    cache::release(block, size);

    EXPECT_EQ(cache::cached_blocks(), 3);
    EXPECT_EQ(cache::cached_bytes(), cache::min_block_size * 3 + cache::max_block_size);
}

TEST_F(TestArenaResource, LargeBlocksAreNotCached)
{
    std::size_t size = cache::max_block_size + 1;
    void *block = cache::acquire(size);
    EXPECT_GT(size, cache::max_block_size);
    EXPECT_EQ(size % cache::min_block_size, 0);
    cache::release(block, size);

    EXPECT_EQ(cache::cached_blocks(), 0);
    EXPECT_EQ(cache::cached_bytes(), 0);
}

TEST_F(TestArenaResource, CachedBlocksAreReused)
{
    std::size_t size = 10000;
    void *block = cache::acquire(size);
    cache::release(block, size);
    EXPECT_EQ(cache::cached_blocks(), 1);

    std::size_t other_size = 9000;
    void *other = cache::acquire(other_size);
    EXPECT_EQ(other, block);
    EXPECT_EQ(other_size, size);
    EXPECT_EQ(cache::cached_blocks(), 0);
    EXPECT_EQ(cache::cached_bytes(), 0);
    cache::release(other, other_size);
}

TEST_F(TestArenaResource, CacheIsBounded)
{
    std::vector<std::pair<void *, std::size_t>> blocks;
    for (std::size_t i = 0; i < cache::max_cached_blocks * 2; ++i) {
        std::size_t size = cache::min_block_size;
        blocks.emplace_back(cache::acquire(size), size);
    }
    for (auto [block, size] : blocks) { cache::release(block, size); }
    EXPECT_EQ(cache::cached_blocks(), cache::max_cached_blocks);

    blocks.clear();
    cache::trim();
    for (std::size_t i = 0; i < 4; ++i) {
        std::size_t size = cache::max_block_size;
        blocks.emplace_back(cache::acquire(size), size);
    }
    for (auto [block, size] : blocks) { cache::release(block, size); }
    EXPECT_EQ(cache::cached_bytes(), cache::max_cached_bytes);
    EXPECT_LE(cache::cached_bytes(), cache::max_cached_bytes);
}

TEST_F(TestArenaResource, BlocksReleasedOnAnotherThread)
{
    std::size_t size = cache::min_block_size;
    void *block = cache::acquire(size);

    std::thread([&]() {
        cache::release(block, size);
        EXPECT_EQ(cache::cached_blocks(), 1);
        // The cache is freed on thread exit
    }).join();

    EXPECT_EQ(cache::cached_blocks(), 0);
}

TEST_F(TestArenaResource, Allocate)
{
    {
        arena_resource arena{cache::min_block_size};

        std::vector<std::pair<char *, std::size_t>> allocations;
        for (std::size_t i = 0; i < 1000; ++i) {
            std::size_t bytes = (i * 37) % 300;
            std::size_t alignment = std::size_t{1} << (i % 5);
            auto *ptr = static_cast<char *>(arena.allocate(bytes, alignment));
            ASSERT_NE(ptr, nullptr);
            EXPECT_TRUE(is_aligned(ptr, alignment));
            std::memset(ptr, static_cast<int>(i & 0xFF), bytes);
            allocations.emplace_back(ptr, bytes);
        }

        // No allocation was overwritten by a later one
        for (std::size_t i = 0; i < allocations.size(); ++i) {
            auto [ptr, bytes] = allocations[i];
            for (std::size_t j = 0; j < bytes; ++j) {
                ASSERT_EQ(static_cast<unsigned char>(ptr[j]), i & 0xFF);
            }
        }

        arena.deallocate(allocations[0].first, allocations[0].second);
    }

    // All blocks went back to the cache
    EXPECT_GT(cache::cached_blocks(), 1);
}

TEST_F(TestArenaResource, ZeroSizedAllocation)
{
    arena_resource arena{cache::min_block_size};
    void *first = arena.allocate(0, 1);
    EXPECT_NE(first, nullptr);
    void *second = arena.allocate(0, 1);
    EXPECT_NE(second, nullptr);
}

TEST_F(TestArenaResource, OverAlignedAllocation)
{
    arena_resource arena{cache::min_block_size};
    for (std::size_t alignment = 1; alignment <= 4096; alignment <<= 1) {
        void *ptr = arena.allocate(8, alignment);
        EXPECT_TRUE(is_aligned(ptr, alignment));
    }

    void *ptr = arena.allocate(cache::min_block_size, 8192);
    EXPECT_TRUE(is_aligned(ptr, 8192));
}

TEST_F(TestArenaResource, LargeAllocation)
{
    arena_resource arena{cache::min_block_size};
    auto *small = static_cast<char *>(arena.allocate(16, 8));

    // Larger than any block class, it gets a dedicated block with no space
    // left after the allocation (2 MiB including the block header)
    const std::size_t large_size = cache::max_block_size * 2 - 16;
    auto *large = static_cast<char *>(arena.allocate(large_size, 8));
    std::memset(large, 0xAA, large_size);

    // The remainder of the first block is still used
    auto *next = static_cast<char *>(arena.allocate(16, 8));
    EXPECT_EQ(next, small + 16);

    arena.release();
    EXPECT_EQ(cache::cached_blocks(), 1);
}

TEST_F(TestArenaResource, BlockSizeDoubles)
{
    {
        arena_resource arena{cache::min_block_size};
        for (std::size_t i = 0; i < 5; ++i) {
            // Each allocation exhausts the current block
            arena.allocate((cache::min_block_size << i) - 64, 16);
        }
    }

    // One block of each of the first 5 classes
    EXPECT_EQ(cache::cached_blocks(), 5);
    EXPECT_EQ(cache::cached_bytes(), cache::min_block_size * 31);
}

#if defined(DDWAF_ASAN)
// Blocks kept in the cache are poisoned, so that ASan reports accesses to the
// memory of a destroyed arena as it would after a free.
TEST_F(TestArenaResource, CachedBlocksArePoisoned)
{
    volatile char *ptr = nullptr;
    {
        arena_resource arena{cache::min_block_size};
        ptr = static_cast<char *>(arena.allocate(16, 8));
        ptr[0] = 1;
    }
    ASSERT_EQ(cache::cached_blocks(), 1);
    EXPECT_DEATH(ptr[0] = 2, "use-after-poison");

    // Reused blocks are accessible again
    arena_resource arena{cache::min_block_size};
    auto *other = static_cast<volatile char *>(arena.allocate(16, 8));
    other[0] = 3;
    EXPECT_EQ(other[0], 3);
}

TEST_F(TestArenaResource, ReleaseWithWrongSizeIsDetected)
{
    std::size_t size = cache::min_block_size;
    void *block = cache::acquire(size);
    EXPECT_DEATH(cache::release(block, size * 2), "isn't a heap block of that size");
    cache::release(block, size);
}
#endif

TEST_F(TestArenaResource, IsEqual)
{
    arena_resource arena{cache::min_block_size};
    arena_resource other{cache::min_block_size};
    EXPECT_TRUE(arena.is_equal(arena));
    EXPECT_FALSE(arena.is_equal(other));
}

} // namespace
