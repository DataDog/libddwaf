// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "output_formatter.hpp"
#include "random.hpp"
#include <iomanip>
#include <iostream>

namespace ddwaf::benchmark {

static constexpr double MILLI = 1e3;
static constexpr double MICRO = 1e6;

void output_csv(const std::map<std::string_view, runner::test_result> &results)
{
    std::cout << "name,average,p0,p75,p90,p95,p99,p100,sd" << std::endl;
    for (const auto &[k, v] : results) {
        std::cout << k << ", " << v.average << "," << v.p0 << "," << v.p50
                  << "," << v.p75 << "," << v.p90 << "," << v.p95 << ","
                  << v.p99 << "," << v.p100 << "," << v.sd << std::endl;
    }
}

void output_json(const std::map<std::string_view, runner::test_result> &results)
{
    // Lazy JSON
    bool start = false;

    std::cout << R"({"seed":)" << random::get_seed()
              << R"(,"last_random_value":)" << random::get()
              << R"(,"results":{)";
    for (const auto &[k, v] : results) {
        if (!start) {
            start = true;
        } else {
            std::cout << ",";
        }

        std::cout << R"(")" << k << R"(":{)"
                  << R"("average":)" << v.average << ","
                  << R"("p0":)" << v.p0 << ","
                  << R"("p50":)" << v.p50 << ","
                  << R"("p75":)" << v.p75 << ","
                  << R"("p90":)" << v.p90 << ","
                  << R"("p95":)" << v.p95 << ","
                  << R"("p99":)" << v.p99 << ","
                  << R"("p100":)" << v.p100 << ","
                  << R"("sd":)" << v.sd << "}";
    }
    std::cout << "}}" << std::endl;
}

// NOLINTBEGIN(*-narrowing-conversions)
void output_human(
    const std::map<std::string_view, runner::test_result> &results)
{
    std::cout << "Seed : " << random::get_seed() << std::endl;
    std::cout << "Last Random Value : " << random::get() << std::endl;
    for (const auto &[k, v] : results) {
        std::cout << "---- " << k << " ----" << std::endl
                  << std::fixed << std::setprecision(3)
                  << "  average      : " << v.average / MICRO << " ms"
                  << std::endl
                  << "  p0           : " << v.p0 / MICRO << " ms" << std::endl
                  << "  p50          : " << v.p50 / MICRO << " ms" << std::endl
                  << "  p75          : " << v.p75 / MICRO << " ms" << std::endl
                  << "  p90          : " << v.p90 / MICRO << " ms" << std::endl
                  << "  p95          : " << v.p95 / MICRO << " ms" << std::endl
                  << "  p99          : " << v.p99 / MICRO << " ms" << std::endl
                  << "  p100         : " << v.p100 / MICRO << " ms" << std::endl
                  << "  s. deviation : " << v.sd / MILLI << " us" << std::endl;
    }
}
// NOLINTEND(*-narrowing-conversions)

} // namespace ddwaf::benchmark
