// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cstddef>
#include <limits>
#include <new>

#include "memory_resource.hpp"

namespace ddwaf::memory {

// Memory for libddwaf's own, transient allocations: transformed strings,
// matcher highlights, tokens, regular expression scratch space and other
// evaluation temporaries, as well as context and subcontext objects. State that
// lives as long as a context or subcontext uses its arena instead.
//
// Blocks of up to max_block_size bytes are served from a cache owned by the
// calling thread, with one free list per power-of-two size class; a cache miss,
// a larger block, or an alignment above alignof(std::max_align_t) goes to
// operator new. Steady-state evaluations therefore do not call into the system
// allocator for these allocations, which matters for allocators with a global
// lock (musl).
//
// A block may be released on a different thread than the one that allocated
// it: it then goes to the cache of the releasing thread. The cache of a thread
// retains at most max_cached_blocks blocks per class and max_cached_bytes in
// total; any other block is freed immediately. The cache is freed when its
// thread exits (see thread_exit::register_callback).
//
// Memory from this resource must never reach the user: the user frees objects
// with the allocator they provided or with the default allocator, which is
// not this resource. The resource only compares equal to itself, so
// dynamic_string::to_object and owned_object::clone copy rather than transfer
// such memory to an output allocator.
namespace internal_block_cache {

inline constexpr std::size_t min_block_size = 16;
// The largest scratch bitmap of RE2's BitState is 32 KiB
inline constexpr std::size_t max_block_size = std::size_t{32} << 10;
inline constexpr std::size_t max_cached_blocks = 128;
inline constexpr std::size_t max_cached_bytes = std::size_t{256} << 10;

// Allocates `bytes` bytes, rounded up to the size class, aligned to
// `alignment`; deallocate must be called with the same values.
void *allocate(std::size_t bytes, std::size_t alignment = alignof(std::max_align_t));
void deallocate(
    void *p, std::size_t bytes, std::size_t alignment = alignof(std::max_align_t)) noexcept;

// Testing helpers: the number of blocks and bytes cached by the calling thread,
// and a way to free them.
std::size_t cached_blocks() noexcept;
std::size_t cached_bytes() noexcept;
void trim() noexcept;

} // namespace internal_block_cache

class internal_resource final : public memory_resource {
public:
    internal_resource() = default;
    ~internal_resource() override = default;
    internal_resource(const internal_resource &) = delete;
    internal_resource(internal_resource &&) = delete;
    internal_resource &operator=(const internal_resource &) = delete;
    internal_resource &operator=(internal_resource &&) = delete;

protected:
    void *do_allocate(std::size_t bytes, std::size_t alignment) override
    {
        return internal_block_cache::allocate(bytes, alignment);
    }

    void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override
    {
        internal_block_cache::deallocate(p, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(const memory_resource &other) const noexcept override
    {
        return this == &other;
    }
};

// The resource for internal allocations (see above).
memory_resource *get_internal_resource() noexcept;

// A stateless allocator over the internal block cache, for standard containers
// holding internal, transient data.
template <typename T> class internal_allocator {
public:
    using value_type = T;

    internal_allocator() noexcept = default;
    template <typename U>
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    internal_allocator(const internal_allocator<U> & /*other*/) noexcept
    {}

    T *allocate(std::size_t n)
    {
        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
            throw std::bad_array_new_length();
        }
        return static_cast<T *>(internal_block_cache::allocate(n * sizeof(T), alignof(T)));
    }

    void deallocate(T *p, std::size_t n) noexcept
    {
        internal_block_cache::deallocate(p, n * sizeof(T), alignof(T));
    }

    template <typename U> bool operator==(const internal_allocator<U> & /*other*/) const noexcept
    {
        return true;
    }
};

} // namespace ddwaf::memory
