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

class timer
{
public:
    // Syscall frequency refers to the number of times clock_gettime is called,
    // the frequency is measured in number of calls to expired. E.g. if the
    // frequency is 16, every 16 calls to expired, the current time will be
    // updated by calling clock_gettime.
    timer(monotonic_clock::time_point exp, uint32_t syscall_frequency = 16):
      expiration_(exp), syscall_frequency_(syscall_frequency)  {}

    bool expired() {
        if (--calls_ == 0) {
            if (expiration_ <= monotonic_clock::now()) {
                return true;
            }
            calls_ = syscall_frequency_;
        }
        return false;
    }
protected:
    monotonic_clock::time_point expiration_;
    const uint32_t syscall_frequency_{16};
    uint32_t calls_{1};
};
#endif // __linux__
}
#endif
