// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

// Memory statistics of the benchmark process, for --memory (see README):
// glibc's mallinfo2(), looked up at run time so that the same binary runs on
// musl, where only the kernel's view (/proc/self/status) is available.

#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace bench {

// All values in bytes; -1 when unavailable.
struct mem_sample {
    // glibc mallinfo2(), summed over all arenas.
    int64_t in_use{-1};     // uordblks + hblkhd: allocated bytes, mmapped chunks included
    int64_t arena{-1};      // arena: non-mmapped bytes obtained from the system
    int64_t mmapped{-1};    // hblkhd: bytes in mmapped chunks
    int64_t free_bytes{-1}; // fordblks: free bytes kept in the arenas
    int64_t keepcost{-1};   // keepcost: releasable top of the main arena
    // Kernel (/proc/self/status).
    int64_t rss{-1};      // VmRSS
    int64_t rss_anon{-1}; // RssAnon
    int64_t hwm{-1};      // VmHWM: peak RSS since start or the last reset_hwm()
};

// Whether mallinfo2() was found (glibc >= 2.33).
bool have_mallinfo();

mem_sample take_sample();

// Resets VmHWM to the current RSS (writes 5 to /proc/self/clear_refs).
bool reset_hwm();

std::string mem_json(const mem_sample &s);

// Samples the process from a background thread at a fixed interval, to find
// the peak and the steady state of a phase. It allocates nothing while it
// runs (the sample buffer is reserved up front), so it does not disturb the
// values it reads. mallinfo2() takes every arena's lock, which slows the
// sampled threads a little; memory runs are never timed.
class mem_sampler {
public:
    mem_sampler() { samples_.reserve(max_samples); }
    mem_sampler(const mem_sampler &) = delete;
    mem_sampler &operator=(const mem_sampler &) = delete;
    ~mem_sampler() { stop(); }

    void start(unsigned interval_us);
    // Takes a last sample and stops the thread.
    void stop();

    // Per field maximum over the samples of the last phase; hwm is read when
    // this is called (VmHWM covers the whole phase when it was reset at its
    // start).
    [[nodiscard]] mem_sample peak() const;
    // Per field median over the second half of the samples of the last phase.
    [[nodiscard]] mem_sample steady() const;
    [[nodiscard]] std::size_t count() const { return samples_.size(); }

private:
    static constexpr std::size_t max_samples = 1 << 16;

    std::vector<mem_sample> samples_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
};

} // namespace bench
