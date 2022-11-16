// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "output_formatter.hpp"
#include "random.hpp"
#include <fstream>
#include <iomanip>
#include <iostream>

namespace ddwaf::benchmark {

namespace {

using output_fn_type = void (*)(
    std::ostream &, const settings &, const std::map<std::string_view, runner::test_result> &);

static constexpr double MILLI = 1e3;
static constexpr double MICRO = 1e6;

void output_csv(std::ostream &o, const settings &s [[maybe_unused]],
    const std::map<std::string_view, runner::test_result> &results)
{
    o << "name,average,p0,p75,p90,p95,p99,p100,sd" << std::endl;
    for (const auto &[k, v] : results) {
        o << k << ", " << v.average << "," << v.p0 << "," << v.p50 << "," << v.p75 << "," << v.p90
          << "," << v.p95 << "," << v.p99 << "," << v.p100 << "," << v.sd << std::endl;
    }
}

void output_json(std::ostream &o, const settings &s,
    const std::map<std::string_view, runner::test_result> &results)
{
    // Lazy JSON
    bool start = false;

    o << R"({"seed":)" << s.seed << R"(,"last_random_value":)" << random::get()
      << R"(,"iterations":)" << s.iterations << R"(,"results":{)";
    for (const auto &[k, v] : results) {
        if (start) {
            o << ",";
        } else {
            start = true;
        }

        o << R"(")" << k << R"(":{)"
          << R"("average":)" << v.average << ","
          << R"("p0":)" << v.p0 << ","
          << R"("p50":)" << v.p50 << ","
          << R"("p75":)" << v.p75 << ","
          << R"("p90":)" << v.p90 << ","
          << R"("p95":)" << v.p95 << ","
          << R"("p99":)" << v.p99 << ","
          << R"("p100":)" << v.p100 << ","
          << R"("sd":)" << v.sd;

        if (!v.samples.empty()) {
            bool sample_start = false;
            o << R"(,"samples":[)";
            for (const auto &sample : v.samples) {
                if (sample_start) {
                    o << ",";
                } else {
                    sample_start = true;
                }
                o << sample;
            }
            o << "]";
        }
        o << "}";
    }
    o << "}}" << std::endl;
}

// NOLINTBEGIN(*-narrowing-conversions)
void output_human(std::ostream &o, const settings &s,
    const std::map<std::string_view, runner::test_result> &results)
{
    o << "Seed : " << s.seed << std::endl
      << "Iterations : " << s.iterations << std::endl
      << "Last Random Value : " << random::get() << std::endl;
    for (const auto &[k, v] : results) {
        o << "---- " << k << " ----" << std::endl
          << std::fixed << std::setprecision(3) << "  average      : " << v.average / MICRO << " ms"
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
} // namespace

void output_results(
    const benchmark::settings &s, const std::map<std::string_view, runner::test_result> &results)
{
    output_fn_type fn = output_json;

    switch (s.format) {
    case output_fmt::json:
        fn = output_json;
        break;
    case output_fmt::human:
        fn = output_human;
        break;
    case output_fmt::csv:
        fn = output_csv;
        break;
    case output_fmt::none:
    default:
        return;
    }

    if (s.output_file.empty()) {
        fn(std::cout, s, results);
    } else {
        std::ofstream fout(s.output_file);
        fn(fout, s, results);
    }
}

} // namespace ddwaf::benchmark
