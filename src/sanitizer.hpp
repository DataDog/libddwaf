// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

// Annotations for AddressSanitizer, for memory which libddwaf recycles itself
// (see arena_block_cache and internal_block_cache) instead of returning it to
// the system allocator, where ASan would otherwise lose track of it: a block
// held in a cache is poisoned, so that any access to memory which has been
// released is reported as it would be after a free; and blocks are checked on
// release against the size with which they were allocated. Without ASan, these
// functions do nothing.

#include <cstddef>

#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define DDWAF_ASAN 1
#  endif
#endif
#if !defined(DDWAF_ASAN) && defined(__SANITIZE_ADDRESS__)
#  define DDWAF_ASAN 1
#endif

#if defined(DDWAF_ASAN)
#  include <cstdio>
#  include <cstdlib>
#  include <sanitizer/allocator_interface.h>
#  include <sanitizer/asan_interface.h>
#endif

namespace ddwaf::memory::sanitizer {

// Makes [ptr, ptr + size) inaccessible
inline void poison([[maybe_unused]] const void *ptr, [[maybe_unused]] std::size_t size) noexcept
{
#if defined(DDWAF_ASAN)
    ASAN_POISON_MEMORY_REGION(ptr, size);
#endif
}

// Makes [ptr, ptr + size) accessible
inline void unpoison([[maybe_unused]] const void *ptr, [[maybe_unused]] std::size_t size) noexcept
{
#if defined(DDWAF_ASAN)
    ASAN_UNPOISON_MEMORY_REGION(ptr, size);
#endif
}

// Aborts unless ptr is the start of a live heap block of exactly the given
// size, as allocated by operator new. This detects a block released with a
// different size than it was allocated with, which would otherwise end up in
// the wrong size class of a cache.
inline void check_block(
    [[maybe_unused]] const void *ptr, [[maybe_unused]] std::size_t size) noexcept
{
#if defined(DDWAF_ASAN)
    if (__sanitizer_get_ownership(ptr) == 0 || __sanitizer_get_allocated_size(ptr) != size) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        std::fprintf(stderr,
            "libddwaf: block %p released as %zu bytes, but it isn't a heap block of that size\n",
            ptr, size);
        __sanitizer_print_stack_trace();
        std::abort();
    }
#endif
}

} // namespace ddwaf::memory::sanitizer
