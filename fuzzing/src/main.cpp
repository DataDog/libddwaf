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
                    {
                        std::unique_lock<std::mutex> lock{mtx_};
                        if (objects_.empty()) {
                            cv_.wait_for(lock, 100ms);
                            continue;
                        }
                        auto [new_input, new_timeout] = objects_.top();
                        objects_.pop();

                        input = new_input;
                        timeout = new_timeout;
                    }

                    run_waf(handle_, input, timeout);
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
            auto [object, timeout] = objects_.top();
            objects_.pop();

            ddwaf_object_free(&object);
        }
        ddwaf_destroy(handle_);
    }

    void push(ddwaf_object object, size_t timeout)
    {
        {
            std::unique_lock<std::mutex> lock{mtx_};
            objects_.push({object, timeout});
        }
        cv_.notify_one();
    }

protected:
    ddwaf_handle handle_;
    std::vector<std::thread> threads_;

    std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> running_{true};
    std::stack<std::pair<ddwaf_object, size_t>> objects_;
};

std::unique_ptr<waf_runner> runner{nullptr};

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

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    size_t timeLeftInUs;
    ddwaf_object args = build_object(bytes, size, verbose, fuzzTimeout, &timeLeftInUs);
    runner->push(args, timeLeftInUs);
    return 0;
}
