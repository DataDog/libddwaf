// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#include "context.hpp"
#include "internal_resource.hpp"
#include "sanitizer.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::memory;

namespace {

namespace cache = internal_block_cache;

bool is_aligned(void *ptr, std::size_t alignment)
{
    return (reinterpret_cast<std::uintptr_t>(ptr) & (alignment - 1)) == 0;
}

class TestInternalResource : public ::testing::Test {
public:
    void SetUp() override { cache::trim(); }
    void TearDown() override { cache::trim(); }
};

TEST_F(TestInternalResource, BlocksAreRoundedUpToClass)
{
    void *block = cache::allocate(1);
    EXPECT_TRUE(is_aligned(block, alignof(std::max_align_t)));
    cache::deallocate(block, 1);
    EXPECT_EQ(cache::cached_blocks(), 1);
    EXPECT_EQ(cache::cached_bytes(), cache::min_block_size);

    block = cache::allocate(cache::min_block_size + 1);
    cache::deallocate(block, cache::min_block_size + 1);
    EXPECT_EQ(cache::cached_blocks(), 2);
    EXPECT_EQ(cache::cached_bytes(), cache::min_block_size * 3);

    block = cache::allocate(cache::max_block_size);
    cache::deallocate(block, cache::max_block_size);
    EXPECT_EQ(cache::cached_blocks(), 3);
    EXPECT_EQ(cache::cached_bytes(), cache::min_block_size * 3 + cache::max_block_size);
}

TEST_F(TestInternalResource, CachedBlocksAreReused)
{
    void *block = cache::allocate(100);
    std::memset(block, 0xAA, 100);
    cache::deallocate(block, 100);

    // Same class (65 to 128 bytes)
    void *other = cache::allocate(128);
    EXPECT_EQ(other, block);
    EXPECT_EQ(cache::cached_blocks(), 0);
    EXPECT_EQ(cache::cached_bytes(), 0);

    // Different class
    void *third = cache::allocate(129);
    EXPECT_NE(third, block);

    cache::deallocate(other, 128);
    cache::deallocate(third, 129);
}

TEST_F(TestInternalResource, LargeAndOverAlignedBlocksAreNotCached)
{
    void *large = cache::allocate(cache::max_block_size + 1);
    std::memset(large, 0xAA, cache::max_block_size + 1);
    cache::deallocate(large, cache::max_block_size + 1);
    EXPECT_EQ(cache::cached_blocks(), 0);

    constexpr std::size_t alignment = alignof(std::max_align_t) * 4;
    void *aligned = cache::allocate(16, alignment);
    EXPECT_TRUE(is_aligned(aligned, alignment));
    cache::deallocate(aligned, 16, alignment);
    EXPECT_EQ(cache::cached_blocks(), 0);
}

TEST_F(TestInternalResource, CacheIsBounded)
{
    std::vector<void *> blocks;
    blocks.reserve(cache::max_cached_blocks * 2);
    for (std::size_t i = 0; i < cache::max_cached_blocks * 2; ++i) {
        blocks.emplace_back(cache::allocate(cache::min_block_size));
    }
    for (auto *block : blocks) { cache::deallocate(block, cache::min_block_size); }
    EXPECT_EQ(cache::cached_blocks(), cache::max_cached_blocks);

    cache::trim();
    EXPECT_EQ(cache::cached_blocks(), 0);
    EXPECT_EQ(cache::cached_bytes(), 0);

    blocks.clear();
    const std::size_t count = cache::max_cached_bytes / cache::max_block_size + 4;
    for (std::size_t i = 0; i < count; ++i) {
        blocks.emplace_back(cache::allocate(cache::max_block_size));
    }
    for (auto *block : blocks) { cache::deallocate(block, cache::max_block_size); }
    EXPECT_EQ(cache::cached_bytes(), cache::max_cached_bytes);
}

TEST_F(TestInternalResource, BlocksReleasedOnAnotherThread)
{
    void *block = cache::allocate(48);

    std::thread([&]() {
        cache::deallocate(block, 48);
        EXPECT_EQ(cache::cached_blocks(), 1);

        // Reused by the releasing thread
        void *other = cache::allocate(64);
        EXPECT_EQ(other, block);
        cache::deallocate(other, 64);
        // The cache is freed on thread exit
    }).join();

    EXPECT_EQ(cache::cached_blocks(), 0);
}

#ifndef _WIN32
TEST_F(TestInternalResource, CacheAfterFork)
{
    void *block = cache::allocate(32);
    cache::deallocate(block, 32);
    ASSERT_EQ(cache::cached_blocks(), 1);

    auto pid = fork();
    ASSERT_NE(pid, -1);
    if (pid == 0) {
        // The child inherits the cache of the forking thread
        bool ok = cache::cached_blocks() == 1;
        void *child_block = cache::allocate(32);
        ok = ok && child_block == block;
        std::memset(child_block, 0x55, 32);
        cache::deallocate(child_block, 32);

        std::vector<std::string> strings;
        for (int i = 0; i < 100; ++i) { strings.emplace_back(200, 'a'); }
        cache::trim();
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        _exit(ok ? 0 : 1);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);

    // The parent's cache is untouched
    EXPECT_EQ(cache::cached_blocks(), 1);
}
#endif

TEST_F(TestInternalResource, Resource)
{
    auto *resource = get_internal_resource();
    EXPECT_EQ(resource, get_internal_resource());
    EXPECT_TRUE(resource->is_equal(*resource));
    EXPECT_FALSE(resource->is_equal(*get_default_resource()));
    EXPECT_FALSE(get_default_resource()->is_equal(*resource));

    for (std::size_t alignment = 1; alignment <= 64; alignment <<= 1) {
        for (std::size_t bytes : {0, 1, 15, 16, 17, 1000, 4096, 4097, 10000}) {
            void *ptr = resource->allocate(bytes, alignment);
            EXPECT_TRUE(is_aligned(ptr, alignment));
            std::memset(ptr, 0xAA, bytes);
            resource->deallocate(ptr, bytes, alignment);
        }
    }
}

TEST_F(TestInternalResource, Allocator)
{
    std::vector<int, internal_allocator<int>> numbers;
    for (int i = 0; i < 1000; ++i) { numbers.emplace_back(i); }
    for (int i = 0; i < 1000; ++i) { EXPECT_EQ(numbers[i], i); }

    EXPECT_TRUE(internal_allocator<int>{} == internal_allocator<char>{});
    EXPECT_THROW((void)internal_allocator<int>{}.allocate(SIZE_MAX / 2), std::bad_array_new_length);
}

#if defined(DDWAF_ASAN)
// Blocks kept in the cache are poisoned, as is the part of a block beyond the
// requested size, so that ASan reports accesses to them as it would without
// the cache.
TEST_F(TestInternalResource, CachedBlocksArePoisoned)
{
    auto *block = static_cast<volatile char *>(cache::allocate(20));
    block[19] = 1;
    EXPECT_DEATH(block[20] = 1, "use-after-poison");

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    cache::deallocate(const_cast<char *>(block), 20);
    ASSERT_EQ(cache::cached_blocks(), 1);
    EXPECT_DEATH(block[0] = 1, "use-after-poison");

    // Reused blocks are accessible again, up to the requested size
    auto *other = static_cast<volatile char *>(cache::allocate(32));
    ASSERT_EQ(other, block);
    other[31] = 1;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    cache::deallocate(const_cast<char *>(other), 32);
}

TEST_F(TestInternalResource, ReleaseWithWrongSizeIsDetected)
{
    void *block = cache::allocate(16);
    EXPECT_DEATH(cache::deallocate(block, 64), "isn't a heap block of that size");
    cache::deallocate(block, 16);
}
#endif

TEST_F(TestInternalResource, ContextsUseTheCache)
{
    test::ruleset_builder rbuilder;
    auto ruleset = rbuilder.build();

    {
        auto *ctx = new context{ruleset};
        auto *sctx = new subcontext{ctx->create_subcontext()};
        delete sctx;
        delete ctx;
    }
    auto blocks = cache::cached_blocks();
    EXPECT_GT(blocks, 0);

    // The next context and subcontext reuse the cached blocks
    {
        auto *ctx = new context{ruleset};
        auto *sctx = new subcontext{ctx->create_subcontext()};
        EXPECT_LT(cache::cached_blocks(), blocks);
        delete sctx;
        delete ctx;
    }
    EXPECT_EQ(cache::cached_blocks(), blocks);
}

} // namespace
