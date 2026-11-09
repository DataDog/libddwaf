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

static void *(*orig_aligned_alloc)(size_t, size_t);
static void *aligned_alloc_polyfill(size_t alignment, size_t size);

void *aligned_alloc(size_t alignment, size_t size) {
	__auto_type f = __atomic_load_n(&orig_aligned_alloc, __ATOMIC_RELAXED);
	if ((uintptr_t)f == (uintptr_t)-1) {
		return aligned_alloc_polyfill(alignment, size);
	} else if (f == 0) {
		typeof(f) orig = dlsym(RTLD_NEXT, "aligned_alloc");
		if (orig != 0) {
			__atomic_store_n(&orig_aligned_alloc, orig, __ATOMIC_RELAXED);
			return orig(alignment, size);
		} else {
			__atomic_store_n(&orig_aligned_alloc, (typeof(f)) -1, __ATOMIC_RELAXED);
			return aligned_alloc_polyfill(alignment, size);
		}
	} else {
		return f(alignment, size);
	}
}

static void *aligned_alloc_polyfill(size_t alignment, size_t size) {
    void *p;
    int rc;
    size_t m;

    /* Pre-2.38 glibc (memalign) semantics: a non-power-of-two alignment is
     * rounded up to the next power of two rather than rejected, and anything
     * below sizeof(void *) (including 0) is raised to it, as posix_memalign
     * requires. Only an alignment with no representable power of two at or
     * above it fails. */
    if (alignment > SIZE_MAX / 2 + 1) {
        errno = EINVAL;
        return NULL;
    }

    /* m = max(alignment, 1) - 1, with the low bits of sizeof(void *) - 1
     * forced on; the power of two is one above m's highest set bit. m is
     * never 0 (clz(0) is undefined), and the check above keeps its top bit
     * clear, so the shift stays below the width of size_t. */
    m = (alignment - (alignment != 0)) | (sizeof(void *) - 1);
    m = (size_t)1 << (sizeof(size_t) * CHAR_BIT - __builtin_clzl(m));

    /* glibc's posix_memalign memory is releasable with free()/realloc(),
     * as aligned_alloc's must be. It returns the error, not via errno. */
    rc = posix_memalign(&p, m, size);
    if (rc != 0) {
        errno = rc;
        return NULL;
    }
    return p;
}

