// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef CLOCK_HPP
#define CLOCK_HPP

#include <atomic>
#include <chrono>

namespace ddwaf
{
#ifndef __linux__
using monotonic_clock = std::chrono::steady_clock;
#else  // linux
struct monotonic_clock
{
    typedef std::chrono::nanoseconds duration;
    typedef duration::rep rep;
    typedef duration::period period;
    typedef std::chrono::time_point<monotonic_clock, duration> time_point;

    static constexpr bool is_steady = true;

    static time_point now() noexcept;

private:
    static std::atomic<bool> warning_issued;
};
#endif // __linux__
}
#endif
