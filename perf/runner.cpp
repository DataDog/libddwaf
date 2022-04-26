// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <algorithm>
#include <iostream>
#include <cmath>
#include <mutex>
#include <atomic>
#include <thread>

#include "runner.hpp"

namespace ddwaf::benchmark
{

namespace {
double percentile(const std::vector<double> &values, unsigned percentile)
{
    std::size_t size = values.size();
    std::size_t index = ceil((size * percentile) / 100.0);
    if (index > 0) {
        index = index - 1;
    }
    return values[index];
}

double standard_deviation(const std::vector<double> &values)
{
    double sd = 0.0;
    auto median = percentile(values, 50);
    for (auto v : values) {
        sd +=  (v - median) * (v - median);
    }
    return sqrt(sd / values.size());
}

}

std::map<std::string_view, runner::test_result> runner::run()
{
    if (threads_ <= 1) { return run_st(); }
    return run_mt();
}

std::map<std::string_view, runner::test_result> runner::run_st()
{
    std::vector<double> times(iterations_);
    std::map<std::string_view, test_result> results;

    for (auto &[name, f] : tests_) {
        double total = 0.0;
        for (std::size_t i = 0; i < iterations_; i++) {
            if (!f->set_up()) {
                std::cerr << "Failed to initialise iteration " << i
                          << " for fixture " << name << std::endl;
                break;
            }

            auto duration = f->test_main();
            times[i] = duration;
            total += duration;

            f->tear_down();
        }

        std::sort(times.begin(), times.end());
        results.emplace(name, test_result{
            total / times.size(),
            percentile(times, 0),
            percentile(times, 50),
            percentile(times, 75),
            percentile(times, 90),
            percentile(times, 95),
            percentile(times, 99),
            percentile(times, 100),
            standard_deviation(times)
        });
    }

    return results;
}

std::map<std::string_view, runner::test_result> runner::run_mt()
{
    std::mutex test_mtx, result_mtx;
    std::map<std::string_view, test_result> results;
    auto test_it = tests_.begin();
    std::thread tid[threads_];

    auto fn = [&](){
        std::vector<double> times(iterations_);

        while (true) {
            std::string_view name;
            fixture_base *f;

            {
                std::lock_guard<std::mutex> lg(test_mtx);
                if (test_it != tests_.end()) {
                    name = test_it->first;
                    f = test_it->second.get();
                    test_it++;
                } else {
                    break;
                }
            }

            // Do work
            double total = 0.0;
            for (std::size_t i = 0; i < iterations_; i++) {
                if (!f->set_up()) {
                    std::cerr << "Failed to initialise iteration " << i
                              << " for fixture " << name << std::endl;
                    break;
                }

                auto duration = f->test_main();
                times[i] = duration;
                total += duration;

                f->tear_down();
            }

            std::sort(times.begin(), times.end());
            test_result tr = {
                total / times.size(),
                percentile(times, 0),
                percentile(times, 50),
                percentile(times, 75),
                percentile(times, 90),
                percentile(times, 95),
                percentile(times, 99),
                percentile(times, 100),
                standard_deviation(times)
            };

            {
                std::lock_guard<std::mutex> lg(result_mtx);
                results.emplace(name, tr);
            }
        }
    };

    for (unsigned i = 0; i < threads_; i++) {
        tid[i] = std::thread(fn);
    }

    for (unsigned i = 0; i < threads_; i++) {
        tid[i].join();
    }

    return results;
}

}
