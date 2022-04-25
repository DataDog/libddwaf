// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <algorithm>
#include <iostream>
#include <cmath>

#include "runner.hpp"

namespace ddwaf::benchmark
{

std::map<std::string_view, runner::test_result> runner::run()
{
    std::map<std::string_view, test_result> results;

    for (std::size_t i = 0; i < tests_.size(); i++) {
        runner_test &test = tests_[i];
        fixture_base &f = *test.f;

        if (!f.global_set_up()) {
            std::cerr << "Failed to initialise fixture: " << test.name << std::endl;
            continue;
        }

        double total = 0.0;
        std::vector<double> times(test.iterations);
        for (std::size_t j = 0; j < test.iterations; j++) {
            if (!f.set_up()) {
                std::cerr << "Failed to initialise iteration " << j
                          << " for fixture " << test.name << std::endl;
                break;
            }

            auto duration = f.test_main();
            times[j] = duration;
            total += duration;

            f.tear_down();
        }

        f.global_tear_down();

        std::sort(times.begin(), times.end());

        double sd = 0.0;
        auto median = times[test.iterations/2 - 1];
        for (auto t : times) {
            sd +=  (t - median) * (t - median);
        }
        sd = sqrt(sd / test.iterations);

        results.emplace(test.name, test_result{
            total / test.iterations,
            times[0],
            median,
            times[(test.iterations * 75) / 100 - 1],
            times[(test.iterations * 90) / 100 - 1],
            times[(test.iterations * 95) / 100 - 1],
            times[(test.iterations * 99) / 100 - 1],
            times[test.iterations - 1],
            sd
        });
    }

    return results;
}

}
