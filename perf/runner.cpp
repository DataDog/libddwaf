// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <algorithm>
#include <atomic>
#include <cmath>
#include <iostream>
#include <mutex>
#include <thread>

#include "runner.hpp"

namespace ddwaf::benchmark {

// NOLINTBEGIN(*-narrowing-conversions,*-magic-numbers)
std::map<std::string, runner::test_result> runner::run()
{
    if (threads_ <= 1) {
        return run_st();
    }
    return run_mt();
}

std::map<std::string, runner::test_result> runner::run_st()
{
    std::map<std::string, test_result> results;
    std::vector<uint64_t> times(iterations_);
    for (auto &[test_name, f] : tests_) {
        std::string name = scenario_ + '.' + test_name;

        for (std::size_t i = 0; i < iterations_; i++) {
            if (!f->set_up()) {
                std::cerr << "Failed to initialise iteration " << i << " for fixture " << name
                          << std::endl;
                break;
            }

            auto duration = f->test_main();
            times[i] = duration;

            f->tear_down();
        }

        results.emplace(std::move(name), times);
    }

    return results;
}

// This method is currently unused as originally it was just meant as a way to
// speed up benchmarking.
// The objective now is to be able to test the performance of the WAF when the
// same instance is being used concurrently. This should allow exercising any
// contention and synchronisation overhead.
std::map<std::string, runner::test_result> runner::run_mt()
{
    std::mutex test_mtx;
    std::mutex result_mtx;
    std::map<std::string, test_result> results;
    auto test_it = tests_.begin();
    std::vector<std::thread> tid(threads_);

    auto fn = [&]() {
        std::vector<uint64_t> times(iterations_);
        while (true) {
            std::string name;
            fixture_base *f;

            {
                std::lock_guard<std::mutex> lg(test_mtx);
                if (test_it != tests_.end()) {
                    name = scenario_ + '.' + test_it->first;
                    f = test_it->second.get();
                    test_it++;
                } else {
                    break;
                }
            }

            // Do work
            for (std::size_t i = 0; i < iterations_; i++) {
                if (!f->set_up()) {
                    std::cerr << "Failed to initialise iteration " << i << " for fixture " << name
                              << std::endl;
                    break;
                }

                auto duration = f->test_main();
                times[i] = duration;

                f->tear_down();
            }

            test_result tr{times};

            {
                std::lock_guard<std::mutex> lg(result_mtx);
                results.emplace(std::move(name), std::move(tr));
            }
        }
    };

    for (unsigned i = 0; i < threads_; i++) { tid[i] = std::thread(fn); }

    for (unsigned i = 0; i < threads_; i++) { tid[i].join(); }

    return results;
}
// NOLINTEND(*-narrowing-conversions,*-magic-numbers)
} // namespace ddwaf::benchmark
