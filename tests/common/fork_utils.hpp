// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.
#pragma once

#ifndef _WIN32

#  include <atomic>
#  include <chrono>
#  include <csignal>
#  include <functional>
#  include <thread>

#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>

namespace ddwaf::test {

// Forks while another thread holds a lock (taken with lock() and released
// with unlock() after a short while) and runs child() in the child process,
// which must return true. Returns whether the child succeeded within a few
// seconds; a child which deadlocks is killed.
inline bool fork_while_locked(const std::function<void()> &lock,
    const std::function<void()> &unlock, const std::function<bool()> &child)
{
    using namespace std::chrono_literals;

    std::atomic<bool> locked{false};
    std::thread holder([&] {
        lock();
        locked = true;
        std::this_thread::sleep_for(200ms);
        unlock();
    });
    while (!locked) { std::this_thread::yield(); }

    const pid_t pid = fork();
    if (pid == 0) {
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        _exit(child() ? 0 : 1);
    }
    holder.join();
    if (pid == -1) {
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() + 5s;
    int status = 0;
    while (waitpid(pid, &status, WNOHANG) == 0) {
        if (std::chrono::steady_clock::now() > deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return false;
        }
        std::this_thread::sleep_for(10ms);
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

} // namespace ddwaf::test

#endif
