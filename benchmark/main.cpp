// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <clock.hpp>
#include <ddwaf.h>
#include <yaml-cpp/node/node.h>

#include "output_formatter.hpp"
#include "random.hpp"
#include "rule_parser.hpp"
#include "run_fixture.hpp"
#include "runner.hpp"
#include "settings.hpp"
#include "utils.hpp"
#include "yaml_helpers.hpp"

namespace benchmark = ddwaf::benchmark;
namespace fs = std::filesystem;
namespace utils = ddwaf::benchmark::utils;

using test_result = ddwaf::benchmark::runner::test_result;

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void print_help_and_exit(std::string_view name, std::string_view error = {})
{
    std::cerr << "Usage: " << name << " [OPTION]...\n"
              << "    --scenarios VALUE     Scenarios repository path\n"
              << "    --fixtures VALUE      Common fixtures repository path\n"
              << "    --runs VALUE          Number of runs per scenario\n"
              << "    --iterations VALUE    Number of iterations per run\n"
              << "    --warmup VALUE        Number of warmup iterations per run\n"
              << "    --format VALUE        Output format: csv, json, human, none\n"
              << "    --output VALUE        Results output file\n";

    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        utils::exit_failure();
    }
    utils::exit_success();
}

benchmark::settings generate_settings(const std::vector<std::string> &args)
{
    benchmark::settings s;

    auto opts = utils::parse_args(args);

    if (opts.contains("help")) {
        print_help_and_exit(args[0]);
    }

    if (!opts.contains("scenarios")) {
        print_help_and_exit(args[0], "Missing option --scenarios");
    } else {
        auto root = opts["scenarios"];
        if (fs::is_directory(root)) {
            for (const auto &dir_entry : fs::directory_iterator{root}) {
                const fs::path &scenario_path = dir_entry;

                if (is_regular_file(scenario_path) && scenario_path.extension() == ".json") {
                    s.scenarios.emplace_back(scenario_path);
                }
            }
        } else {
            s.scenarios.emplace_back(root);
        }
    }

    if (opts.contains("fixtures")) {
        auto root = opts["fixtures"];
        if (fs::is_directory(root)) {
            for (const auto &dir_entry : fs::directory_iterator{root}) {
                const fs::path &scenario_path = dir_entry;

                if (is_regular_file(scenario_path) && scenario_path.extension() == ".json") {
                    s.fixtures.emplace_back(scenario_path);
                }
            }
        } else {
            s.fixtures.emplace_back(root);
        }
    }

    if (opts.contains("format")) {
        auto format = opts["format"];
        if (format == "csv") {
            s.format = benchmark::output_fmt::csv;
        } else if (format == "human") {
            s.format = benchmark::output_fmt::human;
        } else if (format == "json") {
            s.format = benchmark::output_fmt::json;
        } else if (format == "none") {
            s.format = benchmark::output_fmt::none;
        } else {
            print_help_and_exit(args[0], "Unsupported value for --format");
        }
    }

    if (s.format != benchmark::output_fmt::none && opts.contains("output")) {
        s.output_file = opts["output"];
    }

    if (opts.contains("runs")) {
        s.runs = utils::from_string<unsigned>(opts["runs"]);
        if (s.runs == 0) {
            print_help_and_exit(args[0], "Runs should be a positive number");
        }
    }

    if (opts.contains("iterations")) {
        s.iterations = utils::from_string<unsigned>(opts["iterations"]);
        if (s.iterations == 0) {
            print_help_and_exit(args[0], "Iterations should be a positive number");
        }
    }

    if (opts.contains("warmup")) {
        s.warmup_iterations = utils::from_string<unsigned>(opts["warmup"]);
    }

    return s;
}

int main(int argc, char *argv[])
{
    std::vector<std::string> args(argv, argv + argc);

    auto s = generate_settings(args);

    std::unordered_map<std::string, ddwaf_object> common_fixtures;
    for (const auto &fixture : s.fixtures) {
        YAML::Node spec = YAML::Load(utils::read_file(fixture));
        common_fixtures.reserve(common_fixtures.size() + spec.size());
        for (auto it = spec.begin(); it != spec.end(); ++it) {
            common_fixtures.emplace(it->first.as<std::string>(), it->second.as<ddwaf_object>());
        }
    }

    std::map<std::string, std::vector<test_result>> all_results;
    for (unsigned i = 0; i < s.runs; ++i) {
        for (const auto &scenario : s.scenarios) {
            YAML::Node spec = YAML::Load(utils::read_file(scenario));

            auto name = spec["scenario"].as<std::string>();
            auto ruleset = spec["ruleset"].as<ddwaf_object>();

            std::unordered_map<std::string, ddwaf_object> fixtures;
            auto fixtures_spec = spec["fixtures"];
            if (fixtures_spec.IsDefined()) {
                fixtures.reserve(fixtures_spec.size());
                for (auto it = fixtures_spec.begin(); it != fixtures_spec.end(); ++it) {
                    fixtures.emplace(it->first.as<std::string>(), it->second.as<ddwaf_object>());
                }
            }

            ddwaf_config cfg{{0, 0, 0}, {nullptr, nullptr}, nullptr};
            ddwaf_handle handle = ddwaf_init(&ruleset, &cfg, nullptr);
            ddwaf_object_free(&ruleset);
            if (handle == nullptr) {
                std::cerr << "Invalid ruleset file" << std::endl;
                utils::exit_failure();
            }

            benchmark::runner runner(std::move(name), s);
            for (auto &[k, v] : common_fixtures) {
                runner.register_fixture<benchmark::run_fixture>(k, handle, v);
            }

            for (auto &[k, v] : fixtures) {
                runner.register_fixture<benchmark::run_fixture>(k, handle, v);
            }

            auto results = runner.run();

            for (auto &[key, value] : results) {
                auto it = all_results.find(key);
                if (it == all_results.end()) {
                    all_results.emplace(key, std::vector<test_result>{std::move(value)});
                } else {
                    it->second.emplace_back(std::move(value));
                }
            }

            for (auto &[k, v] : fixtures) {
                ddwaf_object_free(&v);
            }

            ddwaf_destroy(handle);
        }
    }

    for (auto &[k, v] : common_fixtures) {
        ddwaf_object_free(&v);
    }

    benchmark::output_results(s, all_results);

    return EXIT_SUCCESS;
}
