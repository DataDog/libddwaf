// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdint>

#include "memory_resource.hpp"

namespace ddwaf::memory {

// Source of the blocks used by arena_resource.
//
// Blocks come in power-of-two size classes, from min_block_size to
// max_block_size. Released blocks are kept in a free list per class, in a
// cache owned by the releasing thread, so that the arenas of the next context
// or subcontext evaluated on that thread are carved from them without calling
// into the system allocator. A block may be released on a different thread
// than the one that acquired it (contexts can migrate between threads).
//
// The cache of a thread retains at most max_cached_blocks blocks per class
// and max_cached_bytes in total; any other block is freed immediately, and so
// are blocks larger than max_block_size, which are never cached. The cache is
// freed when its thread exits (see thread_exit::register_callback).
namespace arena_block_cache {

inline constexpr std::size_t min_block_size = 4096;
inline constexpr std::size_t max_block_size = std::size_t{1} << 20;
inline constexpr std::size_t max_cached_blocks = 8;
inline constexpr std::size_t max_cached_bytes = std::size_t{2} << 20;

// Returns a block of at least `size` bytes, aligned to
// __STDCPP_DEFAULT_NEW_ALIGNMENT__. On return, `size` holds the usable size of
// the block, which is the value that must be passed to release().
void *acquire(std::size_t &size);
void release(void *block, std::size_t size) noexcept;

// Testing helpers: the number of blocks and bytes cached by the calling thread,
// and a way to free them.
std::size_t cached_blocks() noexcept;
std::size_t cached_bytes() noexcept;
void trim() noexcept;

} // namespace arena_block_cache

// A monotonic arena: allocations bump a pointer within the current block and
// deallocations are no-ops; all memory is returned at once when the arena is
// destroyed. Blocks are obtained from the arena_block_cache, starting with one
// of initial_size bytes and doubling in size, up to max_block_size, each time
// a block is exhausted.
//
// This replaces std::pmr::monotonic_buffer_resource for context and subcontext
// memory: that resource requests chunks from its upstream (operator new) with
// sizes that are not powers of two and frees them on destruction, which, on
// every request, makes allocators that return memory to the kernel eagerly
// (musl's mallocng) map and unmap tens of KiB, and contend on their global lock.
class arena_resource final : public memory_resource {
public:
    explicit arena_resource(std::size_t initial_size) noexcept : next_size_(initial_size) {}
    ~arena_resource() override { release(); }

    arena_resource(const arena_resource &) = delete;
    arena_resource(arena_resource &&) = delete;
    arena_resource &operator=(const arena_resource &) = delete;
    arena_resource &operator=(arena_resource &&) = delete;

    // Returns every block to the cache. All memory allocated from the arena
    // becomes invalid.
    void release() noexcept;

    // Testing helper: the total size of the blocks held by the arena
    [[nodiscard]] std::size_t block_bytes() const noexcept
    {
        std::size_t bytes = 0;
        for (const auto *block = blocks_; block != nullptr; block = block->next) {
            bytes += block->size;
        }
        return bytes;
    }

protected:
    struct block_header {
        block_header *next;
        std::size_t size;
    };

    void *do_allocate(std::size_t bytes, std::size_t alignment) override
    {
        // Before the first block, current_ > end_, so that even zero-byte
        // allocations take the slow path.
        auto aligned = (current_ + alignment - 1) & ~(alignment - 1);
        if (aligned <= end_ && bytes <= end_ - aligned) {
            current_ = aligned + bytes;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            return reinterpret_cast<void *>(aligned);
        }
        return allocate_from_new_block(bytes, alignment);
    }

    void do_deallocate(void * /*p*/, std::size_t /*bytes*/, std::size_t /*alignment*/) override {}

    [[nodiscard]] bool do_is_equal(const memory_resource &other) const noexcept override
    {
        return this == &other;
    }

    void *allocate_from_new_block(std::size_t bytes, std::size_t alignment);

    std::uintptr_t current_{1};
    std::uintptr_t end_{0};
    block_header *blocks_{nullptr};
    std::size_t next_size_;
};

} // namespace ddwaf::memory
