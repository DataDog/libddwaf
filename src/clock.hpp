// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

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

class timer
{
public:
    // Syscall period refers to the number of calls to expired() before
    // clock_gettime is called. This approach is only feasible because the 
    // WAF calls expired() quite often, otherwise another solution would be
    // required to minimise syscalls.
    explicit timer(std::chrono::microseconds exp, uint32_t syscall_period = 16):
      expiration_(monotonic_clock::now() + exp), syscall_period_(syscall_period)
    {}

    bool expired() {
        if (!expired_ && --calls_ == 0) {
            if (expiration_ <= monotonic_clock::now()) {
                expired_ = true;
            } else {
                calls_ = syscall_period_;
            }
        }
        return expired_;
    }
protected:
    monotonic_clock::time_point expiration_;
    const uint32_t syscall_period_{16};
    uint32_t calls_{1};
    bool expired_{false};
};
}
