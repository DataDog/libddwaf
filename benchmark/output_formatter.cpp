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

using output_fn_type = void (*)(std::ostream &, const settings &,
    const std::map<std::string, std::vector<runner::test_result>> &);

constexpr double MILLI = 1e3;
constexpr double MICRO = 1e6;

// NOLINTBEGIN(*-narrowing-conversions,*-magic-numbers)
double percentile(const std::vector<uint64_t> &values, unsigned percentile)
{
    std::size_t size = values.size();
    std::size_t index = ceil((size * percentile) / 100.0);
    if (index > 0) {
        index = index - 1;
    }
    return values[index];
}

double standard_deviation(const std::vector<uint64_t> &values, double mean)
{
    double sd = 0.0;
    for (auto v : values) { sd += (v - mean) * (v - mean); }
    return sqrt(sd / values.size());
}

double mean(const std::vector<uint64_t> &values)
{
    double m = 0.0;
    for (auto v : values) { m += v; }
    return m / values.size();
}
// NOLINTEND(*-narrowing-conversions,*-magic-numbers)

void output_json(std::ostream &o, const settings & /*s*/,
    const std::map<std::string, std::vector<runner::test_result>> &results)
{
    std::string_view version = ddwaf_get_version();

    o << R"({"schema_version":"v1","benchmarks":[)";

    bool first_scenario = true;
    for (const auto &[scenario, result_vec] : results) {
        if (first_scenario) {
            first_scenario = false;
        } else {
            o << ",";
        }

        o << R"({"parameters":{)"
          << R"("scenario":")" << scenario << R"(",)"
          << R"("waf_version":")" << version << R"("},"runs":{)";

        bool first_run = true;
        for (std::size_t i = 0; i < result_vec.size(); ++i) {
            const auto &result = result_vec[i];

            if (first_run) {
                first_run = false;
            } else {
                o << ",";
            }

            o << R"(")" << i << R"(":{"execution_time":{"uom":"ns","value":[)";

            bool first_sample = true;
            for (const auto sample : result.samples) {
                if (first_sample) {
                    first_sample = false;
                } else {
                    o << ",";
                }

                o << sample;
            }

            o << R"(]}})";
        }
        o << R"(}})";
    }

    o << R"(]})";
}

void output_csv(std::ostream &o, const settings &s [[maybe_unused]],
    const std::map<std::string, std::vector<runner::test_result>> &results)
{
    o << "name,average,p0,p75,p90,p95,p99,p100,sd" << std::endl;
    for (const auto &[k, vec] : results) {
        std::vector<uint64_t> samples;
        for (const auto &v : vec) {
            samples.reserve(samples.size() + v.samples.size());
            for (auto sample : v.samples) { samples.emplace_back(sample); }
        }
        std::sort(samples.begin(), samples.end());

        double average = mean(samples);

        o << k << ',' << average << ',' << percentile(samples, 0) << ',' << percentile(samples, 50)
          << ',' << percentile(samples, 75) << ',' << percentile(samples, 90) << ','
          << percentile(samples, 95) << ',' << percentile(samples, 99) << ','
          << percentile(samples, 100) << ',' << standard_deviation(samples, average) << '\n';
    }
}

// NOLINTBEGIN(*-narrowing-conversions)
void output_human(std::ostream &o, const settings &s,
    const std::map<std::string, std::vector<runner::test_result>> &results)
{
    o << "Seed : " << s.seed << '\n'
      << "Runs : " << s.runs << '\n'
      << "Iterations : " << s.iterations << '\n'
      << "Last Random Value : " << random::get() << '\n';
    for (const auto &[k, vec] : results) {
        std::vector<uint64_t> samples;
        for (const auto &v : vec) {
            samples.reserve(samples.size() + v.samples.size());
            for (auto sample : v.samples) { samples.emplace_back(sample); }
        }
        std::sort(samples.begin(), samples.end());

        double average = mean(samples);

        o << "---- " << k << "----\n"
          << std::fixed << std::setprecision(3) << "  average      : " << average / MICRO << " ms\n"
          << "  p0           : " << percentile(samples, 0) / MICRO << " ms\n"
          << "  p50          : " << percentile(samples, 50) / MICRO << " ms\n"
          << "  p75          : " << percentile(samples, 75) / MICRO << " ms\n"
          << "  p90          : " << percentile(samples, 90) / MICRO << " ms\n"
          << "  p95          : " << percentile(samples, 95) / MICRO << " ms\n"
          << "  p99          : " << percentile(samples, 99) / MICRO << " ms\n"
          << "  p100         : " << percentile(samples, 100) / MICRO << " ms\n"
          << "  s. deviation : " << standard_deviation(samples, average) / MILLI << " us\n";
    }
}
// NOLINTEND(*-narrowing-conversions)
} // namespace

void output_results(const benchmark::settings &s,
    const std::map<std::string, std::vector<runner::test_result>> &results)
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
