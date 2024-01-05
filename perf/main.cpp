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

#include "object_generator.hpp"
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
using generator_type = benchmark::object_generator::generator_type;

std::map<std::string, benchmark::object_generator::settings> default_tests = {
    {"random.any", {.type = generator_type::random}},
    {"random.long_strings", {.string_length = {512, 1024}, .type = generator_type::random}},
    {"random.deep_containers", {.container_depth = {5, 10}, .type = generator_type::random}},
    {"valid", {.type = generator_type::valid}},
    {"mixed", {.type = generator_type::mixed}},
};

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void print_help_and_exit(std::string_view name, std::string_view error = {})
{
    std::cerr << "Usage: " << name << " [OPTION]...\n"
              << "    --scenarios VALUE     Scenarios repository path\n"
              << "    --runs VALUE          Number of runs per scenario\n"
              << "    --iterations VALUE    Number of iterations per run\n"
              << "    --seed VALUE          Seed for the random number generator\n"
              << "    --format VALUE        Output format: csv, json, human, cbmf, none\n"
              << "    --output VALUE        Results output file\n";

    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        utils::exit_failure();
    }
    utils::exit_success();
}

void print_tests_and_exit()
{
    for (auto &[k, v] : default_tests) { std::cerr << k << std::endl; }
    utils::exit_success();
}

std::map<std::string_view, std::string_view> parse_args(const std::vector<std::string> &args)
{
    std::map<std::string_view, std::string_view> parsed_args;

    for (std::size_t i = 1; i < args.size(); i++) {
        std::string_view arg = args[i];
        if (arg.substr(0, 2) != "--") {
            continue;
        }

        auto assignment = arg.find('=');
        if (assignment != std::string::npos) {
            std::string_view opt_name = arg.substr(2, assignment - 2);
            parsed_args[opt_name] = arg.substr(assignment + 1);
        } else {
            std::string_view opt_name = arg.substr(2);
            parsed_args[opt_name] = {};

            if ((i + 1) < args.size()) {
                std::string_view value = args[i + 1];
                if (value.substr(0, 2) != "--") {
                    parsed_args[opt_name] = value;
                }
            }
        }
    }

    return parsed_args;
}

bool contains(std::map<std::string_view, std::string_view> &opts, std::string_view name)
{
    return opts.find(name) != opts.end();
}

benchmark::settings generate_settings(const std::vector<std::string> &args)
{
    benchmark::settings s;

    auto opts = parse_args(args);

    if (contains(opts, "help")) {
        print_help_and_exit(args[0]);
    }

    if (!contains(opts, "scenarios")) {
        print_help_and_exit(args[0], "Missing option --scenarios");
    } else {
        auto root = opts["scenarios"];
        if (!fs::is_directory(root)) {
            std::cerr << "Scenarios should be a directory" << std::endl;
            utils::exit_failure();
        }

        for (const auto &dir_entry : fs::directory_iterator{root}) {
            const fs::path &scenario_path = dir_entry;

            if (is_regular_file(scenario_path) && scenario_path.extension() == ".json") {
                s.scenarios.push_back(scenario_path);
            }
        }
    }

    if (contains(opts, "format")) {
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

    if (s.format != benchmark::output_fmt::none && contains(opts, "output")) {
        s.output_file = opts["output"];
    }

    if (contains(opts, "runs")) {
        s.runs = utils::from_string<unsigned>(opts["runs"]);
        if (s.runs == 0) {
            print_help_and_exit(args[0], "Runs should be a positive number");
        }
    }

    if (contains(opts, "iterations")) {
        s.iterations = utils::from_string<unsigned>(opts["iterations"]);
        if (s.iterations == 0) {
            print_help_and_exit(args[0], "Iterations should be a positive number");
        }
    }

    if (contains(opts, "seed")) {
        s.seed = utils::from_string<uint64_t>(opts["seed"]);
    } else {
        s.seed = std::random_device()();
    }

    return s;
}

void initialise_runner(
    benchmark::runner &runner, ddwaf_handle handle, benchmark::settings &s, const YAML::Node &spec)
{
    uint32_t addrs_len;
    const auto *const addrs = ddwaf_known_addresses(handle, &addrs_len);

    std::vector<std::string_view> addresses{addrs, addrs + static_cast<size_t>(addrs_len)};

    benchmark::object_generator generator(addresses, spec);

    unsigned num_objects = std::min(s.max_objects, s.iterations);
    for (auto &[k, v] : default_tests) {
        runner.register_fixture<benchmark::run_fixture>(k, handle, generator(v, num_objects));
    }
}

int main(int argc, char *argv[])
{
    std::vector<std::string> args(argv, argv + argc);

    auto s = generate_settings(args);

    benchmark::random::seed(s.seed);

    std::map<std::string, std::vector<test_result>> all_results;
    for (unsigned i = 0; i < s.runs; ++i) {
        for (const auto &scenario : s.scenarios) {
            YAML::Node spec = YAML::Load(utils::read_file(scenario));

            auto name = spec["scenario"].as<std::string>();
            auto ruleset = spec["ruleset"].as<ddwaf_object>();

            ddwaf_config cfg{{0, 0, 0}, {nullptr, nullptr}, nullptr};
            ddwaf_handle handle = ddwaf_init(&ruleset, &cfg, nullptr);
            ddwaf_object_free(&ruleset);
            if (handle == nullptr) {
                std::cerr << "Invalid ruleset file" << std::endl;
                utils::exit_failure();
            }

            benchmark::runner runner(std::move(name), s);
            initialise_runner(runner, handle, s, spec);

            auto results = runner.run();

            for (auto &[key, value] : results) {
                auto it = all_results.find(key);
                if (it == all_results.end()) {
                    all_results.emplace(key, std::vector<test_result>{std::move(value)});
                } else {
                    it->second.emplace_back(std::move(value));
                }
            }

            ddwaf_destroy(handle);
        }
    }

    benchmark::output_results(s, all_results);

    return EXIT_SUCCESS;
}
