// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#if defined(__linux__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

static float ceilf_local(float x)
{
    return __builtin_ceilf(x);
}

#define unlikely(x)    __builtin_expect(!!(x), 0)

typedef float (*ceilf_t)(float);

__attribute__((weak))
float ceilf(float x)
{
    static ceilf_t ceilf_global_;

    // benign race
    if (unlikely(ceilf_global_ == NULL)) {
        void *ceilf_sym = dlsym(RTLD_DEFAULT, "ceilf");
        if (ceilf_sym == NULL || ceilf_sym == &ceilf) {
            ceilf_global_ = &ceilf_local;
        } else {
            ceilf_global_ = (ceilf_t)ceilf_sym;
        }
    }
    return ceilf_global_(x);
}
#endif

