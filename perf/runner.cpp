// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include "runner.hpp"
#include <iomanip>
#include <iostream>

namespace ddwaf::benchmark
{

void runner::run()
{
    for (std::size_t i = 0; i < tests_.size(); i++) {
        double total = 0.0;
        runner_test &test = tests_[i];
        fixture_base &f = *test.f;

        if (!f.global_set_up()) {
            std::cerr << "Failed to initialise fixture: " << test.name << std::endl;
            continue;
        }

        for (std::size_t j = 0; j < test.iterations; j++) {
            if (!f.set_up()) {
                std::cerr << "Failed to initialise iteration " << j
                          << " for fixture " << test.name << std::endl;
                break;
            }

            total += f.test_main();

            f.tear_down();
        }

        f.global_tear_down();

        std::cout << "Test " << test.name << " = "
                  << std::fixed << std::setprecision(3)
                  << (total / test.iterations) / 1000.0 << "us"
                  << std::endl;
    }
}

}
