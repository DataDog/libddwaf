// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#if defined(__linux__) && !defined(__GLIBC__) && (defined(__arm__) || defined(__i386__))

#include <stdlib.h>
#include <features.h>

__attribute__((weak))
int __nanosleep64(void *req, void *rem) {
    (void) req;
    (void) rem;
    abort();
}
__attribute__((weak))
int __nanosleep_time64(void *req, void *rem) {
    return __nanosleep64(req, rem);
}

__attribute__((weak))
int __pthread_cond_timedwait64(void *cond, void *mutex, void *abstime) {
    (void) cond;
    (void) mutex;
    (void) abstime;
    abort();
}
__attribute__((weak))
int __pthread_cond_timedwait_time64(void *cond, void *mutex, void *abstime) {
    return __pthread_cond_timedwait64(cond, mutex, abstime);
}

__attribute__((weak))
void *dlsym(void * handle, const char *name) {
    (void) handle;
    (void) name;
    abort();
}
__attribute__((weak))
void *__dlsym_time64(void *handle, const char *name) {
    return dlsym(handle, name);
}

#endif

#if defined(__linux__)

#if defined(__aarch64__)
// Extracted from https://git.musl-libc.org/cgit/musl/tree/src/math/aarch64/ceilf.c

__attribute__((weak))
float ceilf(float x)
{
	__asm__ ("frintp %s0, %s1" : "=w"(x) : "w"(x));
	return x;
}
#else

#include <stdint.h>

// Extracted from https://git.musl-libc.org/cgit/musl/tree/src/math/ceilf.c

/* fp_force_eval ensures that the input value is computed when that's
   otherwise unused.  To prevent the constant folding of the input
   expression, an additional fp_barrier may be needed or a compilation
   mode that does so (e.g. -frounding-math in gcc). Then it can be
   used to evaluate an expression for its fenv side-effects only.   */

static inline void fp_force_evalf(float x)
{
    volatile float y;
    y = x;
    (void)y;
}

__attribute__((weak))
float ceilf(float x)
{
    union {float f; uint32_t i;} u = {x};
    int e = (int)(u.i >> 23 & 0xff) - 0x7f;
    uint32_t m;

    if (e >= 23) {
        return x;
    }
    if (e >= 0) {
        m = 0x007fffff >> e;
        if ((u.i & m) == 0) {
            return x;
        }
        fp_force_evalf(x + 0x1p120f);
        if (u.i >> 31 == 0){
            u.i += m;
        }
        u.i &= ~m;
    } else {
        fp_force_evalf(x + 0x1p120f);
        if (u.i >> 31) {
            u.f = -0.0;
    } else if (u.i << 1) {
            u.f = 1.0;
        }
    }
    return u.f;
}
#endif
#endif
