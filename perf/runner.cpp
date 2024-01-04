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
namespace {
double percentile(const std::vector<uint64_t> &values, unsigned percentile)
{
    std::size_t size = values.size();
    std::size_t index = ceil((size * percentile) / 100.0);
    if (index > 0) {
        index = index - 1;
    }
    return values[index];
}

double standard_deviation(const std::vector<uint64_t> &values, double average)
{
    double sd = 0.0;
    for (auto v : values) { sd += (v - average) * (v - average); }
    return sqrt(sd / values.size());
}

} // namespace

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
        double average = 0.0;

        for (std::size_t i = 0; i < iterations_; i++) {
            if (!f->set_up()) {
                std::cerr << "Failed to initialise iteration " << i << " for fixture " << name
                          << std::endl;
                break;
            }

            auto duration = f->test_main();
            times[i] = duration;
            average += duration;

            f->tear_down();
        }

        average /= times.size();
        auto samples = store_samples ? times : std::vector<uint64_t>();

        std::sort(times.begin(), times.end());
        results.emplace(std::move(name),
            test_result{average, percentile(times, 0), percentile(times, 50), percentile(times, 75),
                percentile(times, 90), percentile(times, 95), percentile(times, 99),
                percentile(times, 100), standard_deviation(times, average), samples});
    }

    return results;
}

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
            double average = 0.0;
            for (std::size_t i = 0; i < iterations_; i++) {
                if (!f->set_up()) {
                    std::cerr << "Failed to initialise iteration " << i << " for fixture " << name
                              << std::endl;
                    break;
                }

                auto duration = f->test_main();
                times[i] = duration;
                average += duration;

                f->tear_down();
            }

            average /= times.size();
            auto samples = store_samples ? times : std::vector<uint64_t>();
            std::sort(times.begin(), times.end());
            test_result tr = {average, percentile(times, 0), percentile(times, 50),
                percentile(times, 75), percentile(times, 90), percentile(times, 95),
                percentile(times, 99), percentile(times, 100), standard_deviation(times, average),
                samples};

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
