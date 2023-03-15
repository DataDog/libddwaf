// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

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

#include "context_destroy_fixture.hpp"
#include "object_generator.hpp"
#include "output_formatter.hpp"
#include "random.hpp"
#include "rule_parser.hpp"
#include "run_fixture.hpp"
#include "runner.hpp"
#include "settings.hpp"
#include "yaml_helpers.hpp"

namespace benchmark = ddwaf::benchmark;
namespace fs = std::filesystem;

using generator_type = benchmark::object_generator::generator_type;

std::map<std::string, benchmark::object_generator::settings> default_tests = {
    {"run.random.any", {.type = generator_type::random}},
    {"run.random.long_strings", {.string_length = {1024, 4096}, .type = generator_type::random}},
    {"run.random.deep_containers", {.container_depth = {5, 20}, .type = generator_type::random}},
    {"run.valid", {.type = generator_type::valid}},
    {"run.mixed", {.type = generator_type::mixed}},
    {"context_destroy", {.type = generator_type::mixed}},

};

void print_help_and_exit(std::string_view name, std::string_view error = {})
{
    std::cerr << "Usage: " << name << " [OPTION]...\n"
              << "    --rule-repo VALUE     AppSec rules repository path\n"
              << "    --iterations VALUE    Number of iterations per test\n"
              << "    --seed VALUE          Seed for the random number generator\n"
              << "    --format VALUE        Output format: csv, json, human, none\n"
              << "    --list-tests          List all of the available tests\n"
              << "    --test                A comma-separated list of tests to run\n"
              << "    --rtest               A regex matching the tests to run\n"
              << "    --threads VALUE       Number of threads for concurrent "
                 "testing\n"
              << "    --output VALUE        Results output file\n"
              << "    --max-objects VALUE   Maximum number of objects to cache per "
                 "test\n"
              << "    --raw                 Include all samples in output (only "
                 "works with --format=json\n";
    // " "

    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

void print_tests_and_exit()
{
    for (auto &[k, v] : default_tests) { std::cerr << k << std::endl; }
    exit(EXIT_SUCCESS);
}

std::map<std::string_view, std::string_view> parse_args(int argc, char *argv[])
{
    std::map<std::string_view, std::string_view> parsed_args;

    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];
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

            if ((i + 1) < argc) {
                std::string_view value = argv[i + 1];
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

benchmark::settings generate_settings(int argc, char *argv[])
{
    benchmark::settings s;

    auto opts = parse_args(argc, argv);

    if (contains(opts, "help")) {
        print_help_and_exit(argv[0]);
    }

    if (contains(opts, "list-tests")) {
        print_tests_and_exit();
    }

    if (!contains(opts, "rule-repo")) {
        print_help_and_exit(argv[0], "Missing option --rule-repo");
    } else {
        s.rule_repo = opts["rule-repo"];
        if (!fs::is_directory(s.rule_repo)) {
            std::cerr << "Rule repository should be a directory" << std::endl;
            exit(EXIT_FAILURE);
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
            print_help_and_exit(argv[0], "Unsupported value for --format");
        }
    }

    if (s.format != benchmark::output_fmt::none && contains(opts, "output")) {
        s.output_file = opts["output"];
    }

    if (contains(opts, "iterations")) {
        s.iterations = atoi(opts["iterations"].data());
        if (s.iterations == 0) {
            print_help_and_exit(argv[0], "Iterations should be a positive number");
        }
    }

    if (contains(opts, "seed")) {
        s.seed = atoi(opts["seed"].data());
    } else {
        s.seed = std::random_device()();
    }

    if (contains(opts, "threads")) {
        s.threads = atoi(opts["threads"].data());
    }

    if (contains(opts, "max-objects")) {
        s.max_objects = atoi(opts["max-objects"].data());
        if (s.max_objects == 0) {
            print_help_and_exit(argv[0], "Max objects should be a positive number");
        }
    }

    if (contains(opts, "raw")) {
        if (s.format != benchmark::output_fmt::json) {
            print_help_and_exit(argv[0], "Raw only works with json format");
        }
        s.store_samples = true;
    }

    if (contains(opts, "test")) {
        auto test_str = opts["test"];

        std::size_t delimiter = 0;

        std::vector<std::string_view> test_list;
        std::string_view remaining = test_str;
        while ((delimiter = remaining.find(',')) != std::string::npos) {
            auto substr = remaining.substr(0, delimiter);
            if (!substr.empty()) {
                test_list.push_back(substr);
            }
            remaining = remaining.substr(delimiter + 1);
        }

        if (!remaining.empty()) {
            test_list.push_back(remaining);
        }
    }

    if (contains(opts, "rtest")) {
        std::regex test_regex(opts["rtest"].data());
        for (auto &[k, v] : default_tests) {
            if (std::regex_match(k, test_regex)) {
                s.test_list.emplace(k);
            }
        }
    }

    return s;
}

void initialise_runner(benchmark::runner &runner, ddwaf_handle handle, benchmark::settings &s)
{
    uint32_t addrs_len;
    const auto *const addrs = ddwaf_required_addresses(handle, &addrs_len);

    std::vector<std::string_view> addresses{addrs, addrs + static_cast<size_t>(addrs_len)};

    benchmark::object_generator generator(addresses, s.rule_repo / "rules/recommended/");

    unsigned num_objects = std::min(s.max_objects, s.iterations);
    for (auto &[k, v] : default_tests) {
        if (!s.test_list.empty() && s.test_list.find(k) == s.test_list.end()) {
            continue;
        }

        auto objects = generator(v, num_objects);
        if (k.starts_with("run")) {
            runner.register_fixture<benchmark::run_fixture>(k, handle, std::move(objects));
        } else if (k.starts_with("context_destroy")) {
            runner.register_fixture<benchmark::context_destroy_fixture>(
                k, handle, std::move(objects));
        } else {
            std::cerr << "Unknown fixture type: " << k << '\n';
        }
    }
}

int main(int argc, char *argv[])
{
    auto s = generate_settings(argc, argv);

    benchmark::random::seed(s.seed);

    fs::path rule_file = s.rule_repo / "build/recommended.json";

    ddwaf_object rule = benchmark::rule_parser::from_file(rule_file);

    ddwaf_config cfg{{0, 0, 0}, {nullptr, nullptr}, nullptr};
    ddwaf_handle handle = ddwaf_init(&rule, &cfg, nullptr);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        std::cerr << "Invalid ruleset file" << std::endl;
        exit(EXIT_FAILURE);
    }

    benchmark::runner runner(s);
    initialise_runner(runner, handle, s);

    auto results = runner.run();

    benchmark::output_results(s, results);

    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
