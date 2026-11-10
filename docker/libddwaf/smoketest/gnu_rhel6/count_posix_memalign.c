// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

// LD_PRELOADed by the smoke test to count posix_memalign calls. On glibc 2.12,
// which has no aligned_alloc, libddwaf's replacement for it (see
// src/compat/aligned_alloc.c) allocates with posix_memalign, so a non-zero
// count shows the replacement ran.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned long calls;

int posix_memalign(void **ptr, size_t alignment, size_t size)
{
    static int (*real)(void **, size_t, size_t);
    if (real == NULL) {
        real = (int (*)(void **, size_t, size_t))dlsym(RTLD_NEXT, "posix_memalign");
    }
    __sync_fetch_and_add(&calls, 1);
    return real(ptr, alignment, size);
}

__attribute__((destructor)) static void report(void)
{
    (void)fprintf(stderr,"posix_memalign calls: %lu\n", calls);
}
