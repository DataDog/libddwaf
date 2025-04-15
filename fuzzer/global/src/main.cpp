// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ddwaf.h>
#include <iostream>
#include <mutex>
#include <stack>
#include <thread>
#include <vector>

#include "helpers.hpp"
#include "interface.hpp"
#include "object_builder.hpp"

using namespace std::chrono_literals;

bool verbose = false;
bool fuzzTimeout = false;

const char *level_to_str(DDWAF_LOG_LEVEL level)
{
    switch (level) {
    case DDWAF_LOG_TRACE:
        return "trace";
    case DDWAF_LOG_DEBUG:
        return "debug";
    case DDWAF_LOG_ERROR:
        return "error";
    case DDWAF_LOG_WARN:
        return "warn";
    case DDWAF_LOG_INFO:
        return "info";
    case DDWAF_LOG_OFF:
        break;
    }

    return "off";
}

void log_cb(DDWAF_LOG_LEVEL level, const char *function, const char *file, unsigned line,
    const char *message, uint64_t /*length*/)
{
    std::cout << "[" << level_to_str(level) << "][" << file << ":" << function << ":" << line
              << "]: " << message << '\n';
}

class waf_runner {
public:
    waf_runner(ddwaf_handle handle, unsigned num_threads) : handle_(handle)
    {
        if (handle_ == nullptr) {
            __builtin_trap();
        }

        threads_.reserve(num_threads);
        for (unsigned i = 0; i < num_threads; i++) {
            threads_.emplace_back([this]() {
                while (running_) {
                    ddwaf_object input;
                    size_t timeout;
                    bool ephemeral;
                    {
                        std::unique_lock<std::mutex> lock{mtx_};
                        if (objects_.empty()) {
                            cv_.wait_for(lock, 100ms);
                            continue;
                        }
                        auto [new_input, new_ephemeral, new_timeout] = objects_.front();
                        objects_.pop_front();

                        input = new_input;
                        timeout = new_timeout;
                        ephemeral = new_ephemeral;
                    }

                    run_waf(handle_, input, ephemeral, timeout);
                }
            });
        }
    }

    waf_runner(const waf_runner &) = delete;
    waf_runner(waf_runner &&) = delete;
    waf_runner &operator=(const waf_runner &) = delete;
    waf_runner &operator=(waf_runner &&) = delete;

    ~waf_runner()
    {
        running_ = false;
        cv_.notify_all();

        for (auto &t : threads_) { t.join(); }

        while (!objects_.empty()) {
            auto [object, ephemeral, timeout] = objects_.front();
            objects_.pop_front();

            ddwaf_object_free(&object);
        }
        ddwaf_destroy(handle_);
    }

    void push(ddwaf_object object, bool ephemeral, size_t timeout)
    {
        {
            std::unique_lock<std::mutex> lock{mtx_};
            objects_.emplace_back(object, ephemeral, timeout);
        }
        cv_.notify_one();
    }

protected:
    ddwaf_handle handle_;
    std::vector<std::thread> threads_;

    std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> running_{true};
    std::deque<std::tuple<ddwaf_object, bool, size_t>> objects_;
};

std::unique_ptr<waf_runner> runner{nullptr};

void cleanup() {
    runner.reset();
}

extern "C" int LLVMFuzzerInitialize(const int *argc, char ***argv)
{
    for (int i = 0; i < *argc; i++) {
        if (strcmp((*argv)[i], "--V") == 0) {
            verbose = true;
        } else if (strcmp((*argv)[i], "--fuzz_timeout") == 0) {
            fuzzTimeout = true;
        }
    }

    auto *handle = init_waf();

    runner = std::make_unique<waf_runner>(handle, 4);

    // NOLINTNEXTLINE(cert-err33-c)
    std::atexit(cleanup);

    if (verbose) {
        ddwaf_set_log_cb(log_cb, DDWAF_LOG_TRACE);
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    size_t timeLeftInUs;
    ddwaf_object args = build_object(bytes, size, verbose, fuzzTimeout, &timeLeftInUs);

    bool ephemeral = size > 0 && (bytes[0] & 0x01) == 0;
    runner->push(args, ephemeral, timeLeftInUs);
    return 0;
}
