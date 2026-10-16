// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <array>
#include <cstddef>
#include <cstdint>

#include "thread_exit.hpp"

// Only on Linux (glibc and musl) are thread_local variables accessible from
// pthread key destructors: on macOS, dyld frees the thread_local storage of a
// thread from a key destructor of its own, which may run first, after which
// any access allocates fresh storage.
#if !defined(__linux__)
#  define DDWAF_THREAD_EXIT_THREAD_LOCAL 1
#else
#  include <atomic>
#  include <mutex>
#  include <pthread.h>
#endif

namespace ddwaf::thread_exit {

namespace {

// Trivially constructible and destructible, so that accessing it requires no
// TLS initialisation check and registers no destructor.
struct thread_callbacks {
    std::array<callback, max_callbacks> pending;
    std::size_t count;
};

constinit thread_local thread_callbacks callbacks{};

// Returns false if the callbacks of the thread can't be run on exit
bool arm_thread() noexcept;

void run_callbacks() noexcept
{
    // A callback may register further callbacks, which run in turn
    while (callbacks.count > 0) {
        auto cb = callbacks.pending[--callbacks.count];
        cb();
    }
}

#if defined(DDWAF_THREAD_EXIT_THREAD_LOCAL)

struct thread_reaper {
    thread_reaper() = default;
    ~thread_reaper() { run_callbacks(); }

    thread_reaper(const thread_reaper &) = delete;
    thread_reaper(thread_reaper &&) = delete;
    thread_reaper &operator=(const thread_reaper &) = delete;
    thread_reaper &operator=(thread_reaper &&) = delete;

    bool armed{false};
};

thread_local thread_reaper reaper;

bool arm_thread() noexcept
{
    // Registers the destructor of the reaper for this thread
    reaper.armed = true;
    return true;
}

#else

enum class key_state : uint8_t { uncreated, valid, deleted };

constinit pthread_key_t key{};
constinit std::atomic<key_state> state{key_state::uncreated};
constinit std::once_flag key_once{};

void key_destructor(void * /*value*/) { run_callbacks(); }

// Deletes the key when the library is unloaded or the process exits, as its
// destructor is part of the library. Other threads still alive at that point
// won't run their callbacks, but the calling thread runs its own: a thread
// calling exit() doesn't run its key destructors, and its caches would
// otherwise remain allocated (as reported by LeakSanitizer).
struct key_deleter {
    constexpr key_deleter() = default;
    ~key_deleter()
    {
        if (state.exchange(key_state::deleted) == key_state::valid) {
            pthread_key_delete(key);
        }
        run_callbacks();
    }

    key_deleter(const key_deleter &) = delete;
    key_deleter(key_deleter &&) = delete;
    key_deleter &operator=(const key_deleter &) = delete;
    key_deleter &operator=(key_deleter &&) = delete;
};

// NOLINTNEXTLINE(fuchsia-statically-constructed-objects)
constinit key_deleter deleter;

bool arm_thread() noexcept
{
    try {
        std::call_once(key_once, [] {
            if (pthread_key_create(&key, key_destructor) == 0) {
                auto expected = key_state::uncreated;
                if (!state.compare_exchange_strong(expected, key_state::valid)) {
                    // Already being unloaded
                    pthread_key_delete(key);
                }
            }
        });
    } catch (...) {
        return false;
    }

    // The value only needs to be non-null for the destructor to run
    return state.load(std::memory_order_acquire) == key_state::valid &&
           pthread_setspecific(key, &callbacks) == 0;
}

#endif

} // namespace

bool register_callback(callback cb) noexcept
{
    auto &tc = callbacks;
    if (tc.count >= max_callbacks) {
        return false;
    }

    // The key is set (again) whenever the thread goes from no pending
    // callbacks to one, as its value is cleared before its destructor runs.
    if (tc.count == 0 && !arm_thread()) {
        return false;
    }

    tc.pending[tc.count++] = cb;
    return true;
}

} // namespace ddwaf::thread_exit
