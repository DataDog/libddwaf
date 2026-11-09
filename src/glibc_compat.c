// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

typedef void *(*aligned_alloc_fn)(size_t, size_t);

static void *aligned_alloc_polyfill(size_t alignment, size_t size);

// The implementation in use, resolved on first call. Concurrent first calls
// resolve and store the same value, so relaxed ordering suffices.
static aligned_alloc_fn aligned_alloc_impl;

// Hidden: this only serves references from libddwaf's own code (the bundled
// libc++/libc++abi), even when libddwaf.a is linked into another binary. It
// is never exported, so it neither replaces aligned_alloc for the rest of the
// process nor can be returned by the dlsym lookup below.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
__attribute__((visibility("hidden"))) void *aligned_alloc(size_t alignment, size_t size)
{
    aligned_alloc_fn impl = __atomic_load_n(&aligned_alloc_impl, __ATOMIC_RELAXED);
    if (impl == NULL) {
        // Resolve as an ordinary call would, so the result pairs with the
        // free() this code binds to (e.g. an LD_PRELOADed allocator).
        // RTLD_NEXT would skip allocators loaded before us. NULL means the
        // libc predates aligned_alloc (glibc < 2.16).
        impl = (aligned_alloc_fn)dlsym(RTLD_DEFAULT, "aligned_alloc");
        if (impl == NULL) {
            impl = aligned_alloc_polyfill;
        }
        __atomic_store_n(&aligned_alloc_impl, impl, __ATOMIC_RELAXED);
    }
    return impl(alignment, size);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static void *aligned_alloc_polyfill(size_t alignment, size_t size)
{
    // Pre-2.38 glibc (memalign) semantics: a non-power-of-two alignment is
    // rounded up to the next power of two rather than rejected, and anything
    // below sizeof(void *) (including 0) is raised to it, as posix_memalign
    // requires. Only an alignment with no representable power of two at or
    // above it fails.
    if (alignment > SIZE_MAX / 2 + 1) {
        errno = EINVAL;
        return NULL;
    }

    // m = max(alignment, 1) - 1, with the low bits of sizeof(void *) - 1
    // forced on; the power of two is one above m's highest set bit. m is
    // never 0 (clz(0) is undefined), and the check above keeps its top bit
    // clear, so the shift stays below the width of size_t.
    const size_t m = (alignment - (alignment != 0)) | (sizeof(void *) - 1);
    const size_t pow2 = (size_t)1 << (sizeof(size_t) * CHAR_BIT - __builtin_clzl(m));

    // glibc's posix_memalign memory is releasable with free()/realloc(),
    // as aligned_alloc's must be. It returns the error, not via errno.
    void *p = NULL;
    const int rc = posix_memalign(&p, pow2, size);
    if (rc != 0) {
        errno = rc;
        return NULL;
    }
    return p;
}
