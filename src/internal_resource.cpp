// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>

#include "internal_resource.hpp"
#include "memory_resource.hpp"
#include "sanitizer.hpp"
#include "thread_exit.hpp"

namespace ddwaf::memory {

namespace internal_block_cache {

namespace {

constexpr std::size_t num_classes = std::bit_width(max_block_size / min_block_size);

static_assert(std::has_single_bit(min_block_size) && std::has_single_bit(max_block_size));
static_assert(min_block_size >= alignof(std::max_align_t));
static_assert(max_cached_blocks <= std::numeric_limits<uint16_t>::max());

struct free_block {
    free_block *next;
};

enum class cache_state : uint8_t { unused, active, destroyed };

// Trivially constructible and destructible, so that accessing it requires no
// TLS initialisation check. Its contents are freed by reap_thread_cache when
// the thread exits, see thread_exit::register_callback.
struct thread_cache {
    std::array<free_block *, num_classes> heads;
    std::array<uint16_t, num_classes> counts;
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

// Blocks come from operator new rather than from the default resource, which
// the application could replace while blocks are cached. Cached blocks have
// their class size and the default alignment.
void *upstream_allocate(std::size_t size, std::size_t alignment)
{
    if (alignment > __STDCPP_DEFAULT_NEW_ALIGNMENT__) {
        return ::operator new(size, std::align_val_t{alignment});
    }
    return ::operator new(size);
}

void upstream_deallocate(void *p, std::size_t size, std::size_t alignment) noexcept
{
    if (alignment > __STDCPP_DEFAULT_NEW_ALIGNMENT__) {
        ::operator delete(p, size, std::align_val_t{alignment});
        return;
    }
    ::operator delete(p, size);
}

void free_cached_blocks(thread_cache &tc) noexcept
{
    for (std::size_t i = 0; i < num_classes; ++i) {
        auto *block = tc.heads[i];
        while (block != nullptr) {
            sanitizer::unpoison(block, sizeof(free_block));
            auto *next = block->next;
            upstream_deallocate(block, min_block_size << i, alignof(std::max_align_t));
            block = next;
        }
        tc.heads[i] = nullptr;
        tc.counts[i] = 0;
    }
    tc.bytes = 0;
}

} // namespace

void *allocate(std::size_t bytes, std::size_t alignment)
{
    if (bytes > max_block_size || alignment > alignof(std::max_align_t)) [[unlikely]] {
        return upstream_allocate(bytes, alignment);
    }

    auto idx = class_index(bytes);
    const auto size = min_block_size << idx;
    auto &tc = cache;
    auto *block = tc.heads[idx];
    if (block != nullptr) [[likely]] {
        sanitizer::unpoison(block, sizeof(free_block));
        tc.heads[idx] = block->next;
        --tc.counts[idx];
        tc.bytes -= size;
        // Only the requested bytes are accessible
        sanitizer::poison(block, size);
        sanitizer::unpoison(block, bytes);
        return block;
    }

    void *p = upstream_allocate(size, alignof(std::max_align_t));
    sanitizer::poison(p, size);
    sanitizer::unpoison(p, bytes);
    return p;
}

void deallocate(void *p, std::size_t bytes, std::size_t alignment) noexcept
{
    if (p == nullptr) [[unlikely]] {
        return;
    }

    if (bytes > max_block_size || alignment > alignof(std::max_align_t)) [[unlikely]] {
        upstream_deallocate(p, bytes, alignment);
        return;
    }

    auto idx = class_index(bytes);
    auto size = min_block_size << idx;
    sanitizer::check_block(p, size);

    auto &tc = cache;
    if (tc.counts[idx] < max_cached_blocks && tc.bytes + size <= max_cached_bytes &&
        tc.state != cache_state::destroyed) [[likely]] {
        if (tc.state == cache_state::unused) [[unlikely]] {
            if (!thread_exit::register_callback(reap_thread_cache)) {
                // The cache couldn't be freed when the thread exits
                tc.state = cache_state::destroyed;
                upstream_deallocate(p, size, alignof(std::max_align_t));
                return;
            }
            tc.state = cache_state::active;
        }

        sanitizer::unpoison(p, sizeof(free_block));
        tc.heads[idx] = new (p) free_block{tc.heads[idx]};
        ++tc.counts[idx];
        tc.bytes += size;
        // Any later access to the block is a use after free
        sanitizer::poison(p, size);
        return;
    }

    upstream_deallocate(p, size, alignof(std::max_align_t));
}

std::size_t cached_blocks() noexcept
{
    std::size_t count = 0;
    for (auto c : cache.counts) { count += c; }
    return count;
}

std::size_t cached_bytes() noexcept { return cache.bytes; }

void trim() noexcept { free_cached_blocks(cache); }

} // namespace internal_block_cache

namespace {

// The resource is never destroyed: memory may be released from thread_local or
// static destructors running after the destructors of other statics.
union resource_holder {
    constexpr resource_holder() : resource() {}
    // NOLINTNEXTLINE(modernize-use-equals-default)
    ~resource_holder() {}

    resource_holder(const resource_holder &) = delete;
    resource_holder(resource_holder &&) = delete;
    resource_holder &operator=(const resource_holder &) = delete;
    resource_holder &operator=(resource_holder &&) = delete;

    internal_resource resource;
};

// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
constinit resource_holder holder;

} // namespace

memory_resource *get_internal_resource() noexcept { return &holder.resource; }

} // namespace ddwaf::memory
