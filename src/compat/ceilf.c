// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

/* Portions derived from musl libc are licensed as follows:
 *
 * Copyright © 2005-2020 Rich Felker, et al.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#if defined(__linux__)

#  ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#  endif
#  include <dlfcn.h>
#  include <stdatomic.h>
#  include <stdint.h>
#  include <stdlib.h>

#  if defined(__aarch64__)
// Extracted from
// https://git.musl-libc.org/cgit/musl/tree/src/math/aarch64/ceilf.c
static float ceilf_local(float x)
{
    __asm__("frintp %s0, %s1" : "=w"(x) : "w"(x));
    return x;
}
#  else
#    if defined(__x86_64__)
static float ceilf_local_sse41(float x)
{
    float result;
    __asm__("roundss $0x0A, %[x], %[result]"
        : [result] "=x"(result)
        : [x] "x"(x));
    return result;
}

static int cpu_supports_sse41(void)
{
    uint32_t eax = 1;
    uint32_t ecx;

    // clang 8+ assumes that __cpu_model and __cpu_indicator_init bind locally
    // and emits direct relocations incompatible with shared libraries, even
    // when compiling with -fPIC. While libgcc_s/libclang_rt.builtins
    // (compiler-rt) provide these as hidden and therefore non-preemptible
    // definitions, Rust does not link against them and ships with its own
    // compiler intrinsics crate, which provides neither symbol. So avoid
    // __builtin_cpu_supports altogether.
    __asm__("cpuid" : "+a"(eax), "=c"(ecx) : : "ebx", "edx");
    return (ecx & (1U << 19)) != 0;
}
#    endif

/* fp_force_eval ensures that the input value is computed when that's
   otherwise unused. To prevent the constant folding of the input
   expression, an additional fp_barrier may be needed or a compilation
   mode that does so (e.g. -frounding-math in gcc). Then it can be
   used to evaluate an expression for its fenv side-effects only. */
static inline void fp_force_evalf(float x)
{
    volatile float y;
    y = x;
    (void)y;
}

// Extracted from https://git.musl-libc.org/cgit/musl/tree/src/math/ceilf.c
static float ceilf_local(float x)
{
    union {
        float f;
        uint32_t i;
    } u = {x};
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
        if (u.i >> 31 == 0) {
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
#  endif

#  define unlikely(x) __builtin_expect(!!(x), 0)

typedef float (*ceilf_t)(float);

__attribute__((weak)) float ceilf(float x)
{
    static _Atomic(ceilf_t) ceilf_global_;
    ceilf_t ceilf_global =
        atomic_load_explicit(&ceilf_global_, memory_order_relaxed);

    if (unlikely(ceilf_global == NULL)) {
        void *ceilf_sym = dlsym(RTLD_DEFAULT, "ceilf");
        if (ceilf_sym == NULL || ceilf_sym == &ceilf) {
#  if defined(__x86_64__)
            if (cpu_supports_sse41()) {
                ceilf_global = &ceilf_local_sse41;
            } else {
                ceilf_global = &ceilf_local;
            }
#  else
            ceilf_global = &ceilf_local;
#  endif
        } else {
            ceilf_global = (ceilf_t)ceilf_sym;
        }
        atomic_store_explicit(
            &ceilf_global_, ceilf_global, memory_order_relaxed);
    }
    return ceilf_global(x);
}
#endif
