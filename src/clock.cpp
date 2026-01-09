// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <atomic>
#include <cerrno>
#include <chrono>
#ifdef __linux__

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#  define _GNU_SOURCE 1
#  include <ctime>
#  include <dlfcn.h>

#  include "clock.hpp"
#  include "log.hpp"

namespace ddwaf {
namespace {
#  if defined(__aarch64__)
constexpr const char *VDSO_CLOCK_GETTIME = "__kernel_clock_gettime";
#  elif defined(__arm__) || defined(__i386__)
constexpr const char *VDSO_CLOCK_GETTIME = "__vdso_clock_gettime64";
#  else
constexpr const char *VDSO_CLOCK_GETTIME = "__vdso_clock_gettime";
#  endif

// NOLINTNEXTLINE(misc-include-cleaner)
using clock_gettime_t = int (*)(clockid_t, timespec *);
// NOLINTNEXTLINE(misc-include-cleaner)
clock_gettime_t clock_gettime = &::clock_gettime;
} // namespace

monotonic_clock::time_point monotonic_clock::now() noexcept
{
    struct timespec ts {};
    // NOLINTNEXTLINE(misc-include-cleaner)
    const int ret = ddwaf::clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret < 0) {
        bool expected = false;
        if (warning_issued.compare_exchange_strong(expected, true)) {
            DDWAF_ERROR("clock_gettime failed. Errno {}", errno);
        }
        return time_point(std::chrono::seconds(0));
    }
    return time_point(std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec));
}

// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
std::atomic_bool monotonic_clock::warning_issued{};

struct VdsoInitializer {
    VdsoInitializer() noexcept
        : handle(dlopen("linux-vdso.so.1", RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD))
    {
        if (handle != nullptr) {
            void *p = dlsym(handle, VDSO_CLOCK_GETTIME);
            if (p != nullptr) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                ddwaf::clock_gettime = reinterpret_cast<clock_gettime_t>(p);
            }
        }
    }

    ~VdsoInitializer()
    {
        if (handle != nullptr) {
            // NOLINTNEXTLINE(misc-include-cleaner)
            ddwaf::clock_gettime = &::clock_gettime;
            dlclose(handle);
        }
    }

    VdsoInitializer(const VdsoInitializer &) = delete;
    VdsoInitializer &operator=(const VdsoInitializer &) = delete;
    VdsoInitializer(VdsoInitializer &&) = delete;
    VdsoInitializer &operator=(VdsoInitializer &&) = delete;

private:
    void *handle;
};

// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
static const VdsoInitializer vdso_initializer;

} // namespace ddwaf
#endif
