// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>

#include "arena_resource.hpp"
#include "sanitizer.hpp"
#include "thread_exit.hpp"

namespace ddwaf::memory {

namespace arena_block_cache {

namespace {

constexpr std::size_t num_classes = std::bit_width(max_block_size / min_block_size);

static_assert(std::has_single_bit(min_block_size) && std::has_single_bit(max_block_size));
static_assert(max_cached_blocks <= std::numeric_limits<uint8_t>::max());

struct free_block {
    free_block *next;
};

enum class cache_state : uint8_t { unused, active, destroyed };

// Trivially constructible and destructible, so that accessing it requires no
// TLS initialisation check. Its contents are freed by reap_thread_cache when
// the thread exits, see thread_exit::register_callback.
struct thread_cache {
    std::array<free_block *, num_classes> heads;
    std::array<uint8_t, num_classes> counts;
    std::size_t bytes;
    cache_state state;
};

constinit thread_local thread_cache cache{};

void free_cached_blocks(thread_cache &tc) noexcept;

void reap_thread_cache() noexcept
{
    free_cached_blocks(cache);
    cache.state = cache_state::destroyed;
}

std::size_t class_index(std::size_t size) noexcept
{
    return size <= min_block_size ? 0 : std::bit_width((size - 1) / min_block_size);
}

void free_cached_blocks(thread_cache &tc) noexcept
{
    for (std::size_t i = 0; i < num_classes; ++i) {
        auto *block = tc.heads[i];
        while (block != nullptr) {
            sanitizer::unpoison(block, sizeof(free_block));
            auto *next = block->next;
            ::operator delete(block);
            block = next;
        }
        tc.heads[i] = nullptr;
        tc.counts[i] = 0;
    }
    tc.bytes = 0;
}

} // namespace

void *acquire(std::size_t &size)
{
    if (size > max_block_size) {
        if (size > std::numeric_limits<std::size_t>::max() - min_block_size) {
            throw std::bad_alloc();
        }
        size = (size + min_block_size - 1) & ~(min_block_size - 1);
        return ::operator new(size);
    }

    auto idx = class_index(size);
    size = min_block_size << idx;

    auto &tc = cache;
    auto *block = tc.heads[idx];
    if (block != nullptr) {
        sanitizer::unpoison(block, size);
        tc.heads[idx] = block->next;
        --tc.counts[idx];
        tc.bytes -= size;
        return block;
    }

    return ::operator new(size);
}

void release(void *block, std::size_t size) noexcept
{
    if (size <= max_block_size) {
        sanitizer::check_block(block, size);

        auto idx = class_index(size);
        auto &tc = cache;
        if (tc.counts[idx] < max_cached_blocks && tc.bytes + size <= max_cached_bytes &&
            tc.state != cache_state::destroyed) {
            if (tc.state == cache_state::unused) {
                if (!thread_exit::register_callback(reap_thread_cache)) {
                    // The cache couldn't be freed when the thread exits
                    tc.state = cache_state::destroyed;
                    ::operator delete(block);
                    return;
                }
                tc.state = cache_state::active;
            }

            auto *node = new (block) free_block{tc.heads[idx]};
            tc.heads[idx] = node;
            ++tc.counts[idx];
            tc.bytes += size;
            // Any later access to the arena's memory is a use after free
            sanitizer::poison(block, size);
            return;
        }
    }

    ::operator delete(block);
}

std::size_t cached_blocks() noexcept
{
    std::size_t count = 0;
    for (auto c : cache.counts) { count += c; }
    return count;
}

std::size_t cached_bytes() noexcept { return cache.bytes; }

void trim() noexcept { free_cached_blocks(cache); }

} // namespace arena_block_cache

void arena_resource::release() noexcept
{
    auto *block = blocks_;
    while (block != nullptr) {
        auto *next = block->next;
        arena_block_cache::release(block, block->size);
        block = next;
    }
    blocks_ = nullptr;
    current_ = 1;
    end_ = 0;
}

void *arena_resource::allocate_from_new_block(std::size_t bytes, std::size_t alignment)
{
    constexpr std::size_t header_size =
        (sizeof(block_header) + alignof(std::max_align_t) - 1) & ~(alignof(std::max_align_t) - 1);

    // Blocks are only guaranteed the default new alignment
    const std::size_t padding = alignment > __STDCPP_DEFAULT_NEW_ALIGNMENT__ ? alignment - 1 : 0;
    if (bytes > std::numeric_limits<std::size_t>::max() / 2 - padding - header_size) {
        throw std::bad_alloc();
    }
    const std::size_t needed = header_size + padding + bytes;

    std::size_t size = std::max(next_size_, needed);
    void *memory = arena_block_cache::acquire(size);
    blocks_ = new (memory) block_header{blocks_, size};

    if (next_size_ < arena_block_cache::max_block_size) {
        next_size_ = std::min(next_size_ * 2, arena_block_cache::max_block_size);
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto start = reinterpret_cast<std::uintptr_t>(memory);
    auto aligned = (start + header_size + alignment - 1) & ~(alignment - 1);
    auto new_current = aligned + bytes;
    auto new_end = start + size;

    // An allocation larger than the regular block size gets a block of its own;
    // keep bumping from whichever block has more space left.
    auto remaining = current_ <= end_ ? end_ - current_ : 0;
    if (new_end - new_current >= remaining) {
        current_ = new_current;
        end_ = new_end;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<void *>(aligned);
}

} // namespace ddwaf::memory
