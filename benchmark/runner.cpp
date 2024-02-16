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
    std::map<std::string, test_result> results;
    std::vector<uint64_t> times(iterations_);

    for (auto &[test_name, f] : tests_) {
        std::string name = scenario_ + '.' + test_name;

        for (std::size_t i = 0; i < warmup_iterations_; i++) {
            f->set_up();
            f->test_main();
            f->tear_down();
        }

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

} // namespace ddwaf::benchmark
