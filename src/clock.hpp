// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>

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

// Deadline checks are cheap by design: the clock is only read once every
// "period" calls to expired(), which is feasible because the WAF calls
// expired() very often (per rule, per target and per iterated object).
//
// The period adapts between MinPeriod and MaxPeriod: after every clock read
// the timer estimates the average cost of the work done between consecutive
// calls to expired() and picks a period whose expected duration is at most a
// quarter of the remaining budget. Far from the deadline, the clock is
// therefore read rarely; close to it, the timer falls back to MinPeriod and
// the granularity of the check is the same as with a fixed MinPeriod.
//
// A deadline which saturates the clock (e.g. the "infinite" timeout passed
// as UINT64_MAX through the public API) can never be reached, so the clock is
// never read by expired() in that case.
template <std::size_t MinPeriod = 16, std::size_t MaxPeriod = MinPeriod> class base_timer {
public:
    static_assert(MinPeriod > 0 && MinPeriod <= MaxPeriod);
    static_assert(MaxPeriod <= std::numeric_limits<uint32_t>::max());

    explicit base_timer(std::chrono::nanoseconds exp)
        : start_(monotonic_clock::now()), end_(add_saturated(start_, exp)), last_check_(start_),
          calls_(end_ == monotonic_clock::time_point::max() ? never_check : 1)
    {}

    bool expired()
    {
        if (--calls_ != 0) [[likely]] {
            return expired_;
        }
        return check_clock();
    }

    [[nodiscard]] bool expired_before() const { return expired_; }

    [[nodiscard]] monotonic_clock::duration elapsed() const
    {
        return monotonic_clock::now() - start_;
    }

    // A timer which never expires and which doesn't read the clock, neither
    // on construction nor while checking for expiry, so elapsed() is
    // meaningless. Meant for evaluations which must not be interrupted.
    static base_timer unbounded() { return base_timer{}; }

protected:
    // Number of calls before the clock would be read again on a deadline
    // which can't expire; when it reaches zero, it's simply reset.
    static constexpr uint32_t never_check = std::numeric_limits<uint32_t>::max();

    base_timer()
        : end_(monotonic_clock::time_point::max()), last_check_(start_), calls_(never_check)
    {}

    bool check_clock()
    {
        if (expired_ || end_ == monotonic_clock::time_point::max()) {
            calls_ = never_check;
            return expired_;
        }

        const auto now = monotonic_clock::now();
        if (end_ <= now) {
            expired_ = true;
            calls_ = never_check;
            return true;
        }

        calls_ = next_period(now);
        return false;
    }

    uint32_t next_period(monotonic_clock::time_point now)
    {
        if constexpr (MinPeriod == MaxPeriod) {
            return MinPeriod;
        } else {
            // Average cost of the work between two calls of the last period,
            // the first period being a single call.
            const auto calls = std::max<monotonic_clock::rep>(period_, 1);
            const auto per_call =
                std::max<monotonic_clock::rep>((now - last_check_).count() / calls, 1);
            const auto remaining = (end_ - now).count();
            last_check_ = now;

            const auto affordable = remaining / (per_call * 4);
            period_ = static_cast<uint32_t>(std::clamp<monotonic_clock::rep>(affordable,
                static_cast<monotonic_clock::rep>(MinPeriod),
                static_cast<monotonic_clock::rep>(MaxPeriod)));
            return period_;
        }
    }

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

    monotonic_clock::time_point start_{};
    monotonic_clock::time_point end_;
    monotonic_clock::time_point last_check_;
    uint32_t calls_;
    uint32_t period_{1};
    bool expired_{false};
};

using timer = base_timer<16, 64>;

inline timer endless_timer() { return timer{std::chrono::nanoseconds::max()}; }

} // namespace ddwaf
