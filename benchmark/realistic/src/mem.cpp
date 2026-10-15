// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "mem.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(__unix__) || defined(__APPLE__)
#  include <dlfcn.h>
#  include <fcntl.h>
#  include <unistd.h>
#  define BENCH_HAVE_POSIX 1
#endif

namespace bench {
namespace {

// Layout of glibc's struct mallinfo2 (malloc.h). The binary may be built
// against musl's headers, which do not declare it.
struct glibc_mallinfo2 {
    std::size_t arena;
    std::size_t ordblks;
    std::size_t smblks;
    std::size_t hblks;
    std::size_t hblkhd;
    std::size_t usmblks;
    std::size_t fsmblks;
    std::size_t uordblks;
    std::size_t fordblks;
    std::size_t keepcost;
};

using mallinfo2_fn = glibc_mallinfo2 (*)();

mallinfo2_fn mallinfo2_ptr()
{
#ifdef BENCH_HAVE_POSIX
    static const auto fn = reinterpret_cast<mallinfo2_fn>(dlsym(RTLD_DEFAULT, "mallinfo2"));
    return fn;
#else
    return nullptr;
#endif
}

// Parses "Key:   1234 kB" lines of /proc/self/status without allocating.
void read_status(mem_sample &s)
{
#ifdef BENCH_HAVE_POSIX
    char buf[4096];
    const int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { return; }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) { return; }
    buf[n] = '\0';
    auto field = [&](const char *key) -> int64_t {
        const char *p = strstr(buf, key);
        if (p == nullptr) { return -1; }
        p += strlen(key);
        return strtoll(p, nullptr, 10) * 1024;
    };
    s.rss = field("\nVmRSS:");
    s.rss_anon = field("\nRssAnon:");
    s.hwm = field("\nVmHWM:");
#else
    (void)s;
#endif
}

int64_t median_of(std::vector<int64_t> &v)
{
    if (v.empty()) { return -1; }
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

} // namespace

bool have_mallinfo() { return mallinfo2_ptr() != nullptr; }

mem_sample take_sample()
{
    mem_sample s;
    if (auto fn = mallinfo2_ptr(); fn != nullptr) {
        const glibc_mallinfo2 mi = fn();
        s.in_use = static_cast<int64_t>(mi.uordblks + mi.hblkhd);
        s.arena = static_cast<int64_t>(mi.arena);
        s.mmapped = static_cast<int64_t>(mi.hblkhd);
        s.free_bytes = static_cast<int64_t>(mi.fordblks);
        s.keepcost = static_cast<int64_t>(mi.keepcost);
    }
    read_status(s);
    return s;
}

bool reset_hwm()
{
#ifdef BENCH_HAVE_POSIX
    const int fd = open("/proc/self/clear_refs", O_WRONLY | O_CLOEXEC);
    if (fd < 0) { return false; }
    const bool ok = write(fd, "5", 1) == 1;
    close(fd);
    return ok;
#else
    return false;
#endif
}

std::string mem_json(const mem_sample &s)
{
    std::string out = "{";
    auto add = [&](const char *k, int64_t v) {
        if (out.size() > 1) { out += ", "; }
        out += "\"";
        out += k;
        out += "\": ";
        out += v < 0 ? std::string("null") : std::to_string(v);
    };
    add("in_use", s.in_use);
    add("arena", s.arena);
    add("mmapped", s.mmapped);
    add("free", s.free_bytes);
    add("keepcost", s.keepcost);
    add("rss", s.rss);
    add("rss_anon", s.rss_anon);
    add("hwm", s.hwm);
    return out + "}";
}

void mem_sampler::start(unsigned interval_us)
{
    stop();
    samples_.clear();
    stop_.store(false);
    thread_ = std::thread([this, interval_us]() {
        while (!stop_.load(std::memory_order_relaxed)) {
            if (samples_.size() < max_samples) { samples_.push_back(take_sample()); }
            std::this_thread::sleep_for(std::chrono::microseconds(interval_us));
        }
    });
}

void mem_sampler::stop()
{
    if (!thread_.joinable()) { return; }
    stop_.store(true);
    thread_.join();
    if (samples_.size() < max_samples) { samples_.push_back(take_sample()); }
}

mem_sample mem_sampler::peak() const
{
    mem_sample p;
    for (const auto &s : samples_) {
        p.in_use = std::max(p.in_use, s.in_use);
        p.arena = std::max(p.arena, s.arena);
        p.mmapped = std::max(p.mmapped, s.mmapped);
        p.free_bytes = std::max(p.free_bytes, s.free_bytes);
        p.keepcost = std::max(p.keepcost, s.keepcost);
        p.rss = std::max(p.rss, s.rss);
        p.rss_anon = std::max(p.rss_anon, s.rss_anon);
    }
    mem_sample now;
    read_status(now);
    p.hwm = now.hwm;
    return p;
}

mem_sample mem_sampler::steady() const
{
    mem_sample m;
    if (samples_.empty()) { return m; }
    const std::size_t from = samples_.size() / 2;
    std::vector<int64_t> v;
    v.reserve(samples_.size() - from);
    auto med = [&](int64_t mem_sample::*field) {
        v.clear();
        for (std::size_t i = from; i < samples_.size(); ++i) { v.push_back(samples_[i].*field); }
        return median_of(v);
    };
    m.in_use = med(&mem_sample::in_use);
    m.arena = med(&mem_sample::arena);
    m.mmapped = med(&mem_sample::mmapped);
    m.free_bytes = med(&mem_sample::free_bytes);
    m.keepcost = med(&mem_sample::keepcost);
    m.rss = med(&mem_sample::rss);
    m.rss_anon = med(&mem_sample::rss_anon);
    m.hwm = med(&mem_sample::hwm);
    return m;
}

} // namespace bench
