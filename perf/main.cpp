// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ddwaf.h>
#include <clock.hpp>

#include "object_generator.hpp"
#include "output_formatter.hpp"
#include "random.hpp"
#include "rule_parser.hpp"
#include "runner.hpp"
#include "run_fixture.hpp"

using namespace ddwaf;

namespace fs = std::filesystem;

using generator_type = benchmark::object_generator::generator_type;

std::map<std::string, benchmark::object_generator::settings> default_tests = {
    {"run.random.depth_s.object_s.string_s", {{0, 1}, {0, 32}, {0, 32}, 32, generator_type::random}},
    {"run.random.depth_s.object_s.string_m", {{0, 1}, {0, 32}, {33, 512}, 32, generator_type::random}},
    {"run.random.depth_s.object_s.string_l", {{0, 1}, {0, 32}, {513, 1024}, 32, generator_type::random}},
    {"run.random.depth_s.object_m.string_s", {{0, 1}, {33, 128}, {0, 32}, 128, generator_type::random}},
    {"run.random.depth_s.object_m.string_m", {{0, 1}, {33, 128}, {33, 512}, 128, generator_type::random}},
    {"run.random.depth_s.object_m.string_l", {{0, 1}, {33, 128}, {513, 1024}, 128, generator_type::random}},
    {"run.random.depth_s.object_l.string_s", {{0, 1}, {129, 256}, {0, 32}, 512, generator_type::random}},
    {"run.random.depth_s.object_l.string_m", {{0, 1}, {129, 256}, {33, 512}, 512, generator_type::random}},
    {"run.random.depth_s.object_l.string_l", {{0, 1}, {129, 256}, {513, 1024}, 512, generator_type::random}},
    {"run.random.depth_m.object_s.string_s", {{2, 5}, {0, 32}, {0, 32}, 32, generator_type::random}},
    {"run.random.depth_m.object_s.string_m", {{2, 5}, {0, 32}, {33, 512}, 32, generator_type::random}},
    {"run.random.depth_m.object_s.string_l", {{2, 5}, {0, 32}, {513, 1024}, 32, generator_type::random}},
    {"run.random.depth_m.object_m.string_s", {{2, 5}, {33, 128}, {0, 32}, 128, generator_type::random}},
    {"run.random.depth_m.object_m.string_m", {{2, 5}, {33, 128}, {33, 512}, 128, generator_type::random}},
    {"run.random.depth_m.object_m.string_l", {{2, 5}, {33, 128}, {513, 1024}, 128, generator_type::random}},
    {"run.random.depth_m.object_l.string_s", {{2, 5}, {129, 256}, {0, 32}, 512, generator_type::random}},
    {"run.random.depth_m.object_l.string_m", {{2, 5}, {129, 256}, {33, 512}, 512, generator_type::random}},
    {"run.random.depth_m.object_l.string_l", {{2, 5}, {129, 256}, {513, 1024}, 512, generator_type::random}},
    {"run.random.depth_l.object_s.string_s", {{6, 20}, {0, 32}, {0, 32}, 32, generator_type::random}},
    {"run.random.depth_l.object_s.string_m", {{6, 20}, {0, 32}, {33, 512}, 32, generator_type::random}},
    {"run.random.depth_l.object_s.string_l", {{6, 20}, {0, 32}, {513, 1024}, 32, generator_type::random}},
    {"run.random.depth_l.object_m.string_s", {{6, 20}, {33, 128}, {0, 32}, 128, generator_type::random}},
    {"run.random.depth_l.object_m.string_m", {{6, 20}, {33, 128}, {33, 512}, 128, generator_type::random}},
    {"run.random.depth_l.object_m.string_l", {{6, 20}, {33, 128}, {513, 1024}, 128, generator_type::random}},
    {"run.random.depth_l.object_l.string_s", {{6, 20}, {129, 256}, {0, 32}, 512, generator_type::random}},
    {"run.random.depth_l.object_l.string_m", {{6, 20}, {129, 256}, {33, 512}, 512, generator_type::random}},
    {"run.random.depth_l.object_l.string_l", {{6, 20}, {129, 256}, {513, 1024}, 512, generator_type::random}},
    {"run.random.depth_any.object_any.string_any", {{0, 20}, {0, 256}, {0, 1024}, 512, generator_type::random}},
    {"run.valid", {{0, 20}, {0, 256}, {0, 1024}, 512, generator_type::valid}},
    {"run.mixed.depth_s.object_s.string_s", {{0, 1}, {0, 32}, {0, 32}, 32, generator_type::mixed}},
    {"run.mixed.depth_s.object_s.string_m", {{0, 1}, {0, 32}, {33, 512}, 32, generator_type::mixed}},
    {"run.mixed.depth_s.object_s.string_l", {{0, 1}, {0, 32}, {513, 1024}, 32, generator_type::mixed}},
    {"run.mixed.depth_s.object_m.string_s", {{0, 1}, {33, 128}, {0, 32}, 128, generator_type::mixed}},
    {"run.mixed.depth_s.object_m.string_m", {{0, 1}, {33, 128}, {33, 512}, 128, generator_type::mixed}},
    {"run.mixed.depth_s.object_m.string_l", {{0, 1}, {33, 128}, {513, 1024}, 128, generator_type::mixed}},
    {"run.mixed.depth_s.object_l.string_s", {{0, 1}, {129, 256}, {0, 32}, 512, generator_type::mixed}},
    {"run.mixed.depth_s.object_l.string_m", {{0, 1}, {129, 256}, {33, 512}, 512, generator_type::mixed}},
    {"run.mixed.depth_s.object_l.string_l", {{0, 1}, {129, 256}, {513, 1024}, 512, generator_type::mixed}},
    {"run.mixed.depth_m.object_s.string_s", {{2, 5}, {0, 32}, {0, 32}, 32, generator_type::mixed}},
    {"run.mixed.depth_m.object_s.string_m", {{2, 5}, {0, 32}, {33, 512}, 32, generator_type::mixed}},
    {"run.mixed.depth_m.object_s.string_l", {{2, 5}, {0, 32}, {513, 1024}, 32, generator_type::mixed}},
    {"run.mixed.depth_m.object_m.string_s", {{2, 5}, {33, 128}, {0, 32}, 128, generator_type::mixed}},
    {"run.mixed.depth_m.object_m.string_m", {{2, 5}, {33, 128}, {33, 512}, 128, generator_type::mixed}},
    {"run.mixed.depth_m.object_m.string_l", {{2, 5}, {33, 128}, {513, 1024}, 128, generator_type::mixed}},
    {"run.mixed.depth_m.object_l.string_s", {{2, 5}, {129, 256}, {0, 32}, 512, generator_type::mixed}},
    {"run.mixed.depth_m.object_l.string_m", {{2, 5}, {129, 256}, {33, 512}, 512, generator_type::mixed}},
    {"run.mixed.depth_m.object_l.string_l", {{2, 5}, {129, 256}, {513, 1024}, 512, generator_type::mixed}},
    {"run.mixed.depth_l.object_s.string_s", {{6, 20}, {0, 32}, {0, 32}, 32, generator_type::mixed}},
    {"run.mixed.depth_l.object_s.string_m", {{6, 20}, {0, 32}, {33, 512}, 32, generator_type::mixed}},
    {"run.mixed.depth_l.object_s.string_l", {{6, 20}, {0, 32}, {513, 1024}, 32, generator_type::mixed}},
    {"run.mixed.depth_l.object_m.string_s", {{6, 20}, {33, 128}, {0, 32}, 128, generator_type::mixed}},
    {"run.mixed.depth_l.object_m.string_m", {{6, 20}, {33, 128}, {33, 512}, 128, generator_type::mixed}},
    {"run.mixed.depth_l.object_m.string_l", {{6, 20}, {33, 128}, {513, 1024}, 128, generator_type::mixed}},
    {"run.mixed.depth_l.object_l.string_s", {{6, 20}, {129, 256}, {0, 32}, 512, generator_type::mixed}},
    {"run.mixed.depth_l.object_l.string_m", {{6, 20}, {129, 256}, {33, 512}, 512, generator_type::mixed}},
    {"run.mixed.depth_l.object_l.string_l", {{6, 20}, {129, 256}, {513, 1024}, 512, generator_type::mixed}},
    {"run.mixed.depth_any.object_any.string_any", {{0, 20}, {0, 256}, {0, 1024}, 512, generator_type::mixed}},
};

struct process_settings {
    fs::path rule_repo;
    std::unordered_set<std::string_view> test_list;
    benchmark::output_fn_type output_fn{benchmark::output_json};
    unsigned iterations{100};
    unsigned long seed;
    unsigned threads{0};
    unsigned max_objects{100};
    ddwaf_handle handle;
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
              << "    --threads VALUE       Number of threads for concurrent testing\n"
              << "    --max-objects VALUE   Maximum number of objects to cache per test\n";
              // "                                                                                 "

    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

void print_tests_and_exit()
{
    for (auto &[k, v] : default_tests) {
        std::cerr << k << std::endl;
    }
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

process_settings generate_process_settings(int argc, char *argv[])
{
    process_settings s;

    auto opts = parse_args(argc, argv);

    std::cerr << "Settings:" << std::endl;
    for (auto &[k, v] : opts) {
       std::cerr << "[" << k << "] = " << v << std::endl;
    }

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
            s.output_fn = benchmark::output_csv;
        } else if (format == "human") {
            s.output_fn = benchmark::output_human;
        } else if (format == "json") {
            s.output_fn = benchmark::output_json;
        } else if (format == "none") {
            s.output_fn = nullptr;
        } else {
            print_help_and_exit(argv[0], "Unsupported value for --format");
        }
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

void initialise_runner(benchmark::runner &runner, ddwaf_handle handle,
    process_settings &s)
{
    uint32_t addrs_len;
    auto addrs = ddwaf_required_addresses(handle, &addrs_len);

    std::vector<std::string_view> addresses{
        addrs, addrs + static_cast<size_t>(addrs_len)};

    benchmark::object_generator generator(addresses,
        s.rule_repo / "rules/recommended/");

    unsigned num_objects = std::min(s.max_objects, s.iterations);
    for (auto &[k, v] : default_tests) {
        if (!s.test_list.empty() && s.test_list.find(k) == s.test_list.end()) {
            continue;
        }

        runner.register_fixture<benchmark::run_fixture>(k, handle,
            generator(v, num_objects));
    }
}

int main(int argc, char *argv[])
{
    auto s = generate_process_settings(argc, argv);

    benchmark::random::seed(s.seed);

    fs::path rule_file = s.rule_repo / "build/recommended.json";

    ddwaf_object rule = benchmark::rule_parser::from_file(rule_file);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        std::cerr << "Invalid ruleset file" << std::endl;
        exit(EXIT_FAILURE);
    }

    benchmark::runner runner(s.iterations, s.threads);
    initialise_runner(runner, handle, s);
    auto results = runner.run();

    if (s.output_fn) {
        s.output_fn(results);
    }

    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
