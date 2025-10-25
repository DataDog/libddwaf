// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

#if defined __has_builtin
#  if __has_builtin(__builtin_add_overflow)
#    define HAS_BUILTIN_ADD_OVERFLOW
#  endif
#endif

namespace ddwaf {
#ifndef __linux__
using monotonic_clock = std::chrono::steady_clock;
#else  // linux
struct monotonic_clock {
    using duration = std::chrono::nanoseconds;
    using rep = duration::rep;
    using period = duration::period;
    using time_point = std::chrono::time_point<monotonic_clock, duration>;

    static constexpr bool is_steady = true;

    static time_point now() noexcept;

private:
    static std::atomic<bool> warning_issued;
};
#endif // __linux__

// Syscall period refers to the number of calls to expired() before
// clock_gettime is called. This approach is only feasible because the
// WAF calls expired() quite often, otherwise another solution would be
// required to minimise syscalls.
template <std::size_t SyscallPeriod = 16> class base_timer {
public:
    explicit base_timer(std::chrono::nanoseconds exp)
        : start_(monotonic_clock::now()), end_(add_saturated(start_, exp))
    {}

    bool expired()
    {
        if (!expired_ && --calls_ == 0) {
            if (end_ <= monotonic_clock::now()) {
                expired_ = true;
            } else {
                calls_ = SyscallPeriod;
            }
        }
        return expired_;
    }

    [[nodiscard]] bool expired_before() const { return expired_; }

    [[nodiscard]] monotonic_clock::duration elapsed() const
    {
        return monotonic_clock::now() - start_;
    }

protected:
    static monotonic_clock::time_point add_saturated(
        monotonic_clock::time_point augend, std::chrono::nanoseconds addend)
    {
#ifdef HAS_BUILTIN_ADD_OVERFLOW
        using duration = monotonic_clock::duration;

        const duration::rep augend_count = augend.time_since_epoch().count();
        const duration::rep addend_count = addend.count();
        duration::rep result;

        if (__builtin_add_overflow(augend_count, addend_count, &result)) {
            return monotonic_clock::time_point::max();
        }

        return monotonic_clock::time_point(duration(result));
#else
        return (addend > (monotonic_clock::time_point::max() - augend))
                   ? monotonic_clock::time_point::max()
                   : augend + addend;
#endif
    }

    monotonic_clock::time_point start_;
    monotonic_clock::time_point end_;
    uint32_t calls_{1};
    bool expired_{false};
};

using timer = base_timer<16>;

inline timer endless_timer() { return timer{std::chrono::nanoseconds::max()}; }

} // namespace ddwaf
