// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include <stdlib.h>
#include <stdint.h>

#if defined(__linux__) && !defined(__GLIBC__) && (defined(__arm__) || defined(__i386__))

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
/* fp_force_eval ensures that the input value is computed when that's
   otherwise unused.  To prevent the constant folding of the input
   expression, an additional fp_barrier may be needed or a compilation
   mode that does so (e.g. -frounding-math in gcc). Then it can be
   used to evaluate an expression for its fenv side-effects only.   */

#ifndef fp_force_evalf
#define fp_force_evalf fp_force_evalf
static inline void fp_force_evalf(float x)
{
    volatile float y;
    y = x;
    (void)y;
}
#endif

#ifndef fp_force_eval
#define fp_force_eval fp_force_eval
static inline void fp_force_eval(double x)
{
    volatile double y;
    y = x;
    (void)y;
}
#endif

#ifndef fp_force_evall
#define fp_force_evall fp_force_evall
static inline void fp_force_evall(long double x)
{
    volatile long double y;
    y = x;
    (void)y;
}
#endif

#define FORCE_EVAL(x) do {                        \
    if (sizeof(x) == sizeof(float)) {         \
        fp_force_evalf(x);                \
    } else if (sizeof(x) == sizeof(double)) { \
        fp_force_eval(x);                 \
    } else {                                  \
        fp_force_evall(x);                \
    }                                         \
} while(0)

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
        FORCE_EVAL(x + 0x1p120f);
        if (u.i >> 31 == 0){
            u.i += m;
        }
        u.i &= ~m;
    } else {
        FORCE_EVAL(x + 0x1p120f);
        if (u.i >> 31) {
            u.f = -0.0;
    } else if (u.i << 1) {
            u.f = 1.0;
        }
    }
    return u.f;
}
#endif
