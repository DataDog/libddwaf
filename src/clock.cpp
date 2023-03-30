// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "clock.hpp"

#ifdef __linux__

#  include <system_error>

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#  define _GNU_SOURCE 1
#  include <ctime>
#  include <dlfcn.h>
#  include <log.hpp>

#ifdef __aarch64__
#  define CLOCK_GETTIME "__kernel_clock_gettime"
#else
#  define CLOCK_GETTIME "__vdso_clock_gettime"
#endif

namespace ddwaf {
using clock_gettime_t = int (*)(clockid_t, timespec *);

static clock_gettime_t clock_gettime = &::clock_gettime;

monotonic_clock::time_point monotonic_clock::now() noexcept
{
    struct timespec ts {};
    const int ret = ddwaf::clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret < 0) {
        bool expected = false;
        if (warning_issued.compare_exchange_strong(expected, true)) {
            DDWAF_ERROR("clock_gettime failed. Errno %d}", errno);
        }
        return time_point(std::chrono::seconds(0));
    }
    return time_point(std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec));
}

// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
std::atomic_bool monotonic_clock::warning_issued{};

struct VdsoInitializer {
    VdsoInitializer() noexcept
    {
        void *p = dlsym(RTLD_DEFAULT, CLOCK_GETTIME);
        if (p != nullptr) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            ddwaf::clock_gettime = reinterpret_cast<clock_gettime_t>(p);
        }
    }

    VdsoInitializer(const VdsoInitializer &) = delete;
    VdsoInitializer &operator=(const VdsoInitializer &) = delete;
    VdsoInitializer(VdsoInitializer &&) = delete;
    VdsoInitializer &operator=(VdsoInitializer &&) = delete;
};

// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
static const VdsoInitializer vdso_initializer;

} // namespace ddwaf
#endif
