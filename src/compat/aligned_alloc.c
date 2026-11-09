// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

// The statically bundled C++ runtime calls aligned_alloc, which glibc < 2.16
// lacks. Its references are redirected here, following the linker's --wrap
// convention: references to aligned_alloc become __wrap_aligned_alloc, and
// __real_aligned_alloc becomes the real aligned_alloc. libddwaf.so is linked
// with -Wl,--wrap=aligned_alloc; for the bundled libddwaf.a, the release
// packaging applies the same renaming with objcopy.
//
// libddwaf must not define aligned_alloc itself: in a static link, that
// definition would take the place of libc's for the whole program, and libc's
// posix_memalign (which musl implements with aligned_alloc) would then recurse
// into the polyfill below.

// Weak, so that libddwaf links and loads where libc lacks aligned_alloc: the
// reference then resolves to NULL. Otherwise it resolves like any ordinary
// call, so it pairs with the free() libddwaf binds to (e.g. an LD_PRELOADed
// allocator's).
extern void *__real_aligned_alloc(size_t alignment, size_t size) __attribute__((weak));

static void *aligned_alloc_polyfill(size_t alignment, size_t size);

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
__attribute__((visibility("hidden"))) void *__wrap_aligned_alloc(size_t alignment, size_t size)
{
    if (__real_aligned_alloc != NULL) {
        return __real_aligned_alloc(alignment, size);
    }
    return aligned_alloc_polyfill(alignment, size);
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
