// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <cstdlib>
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

std::map<std::string, benchmark::object_generator::limits> default_tests = {
    {"shallow_depth.small_objects.small_strings", {{0, 1}, {0, 32}, {0, 32}, 32}},
    {"shallow_depth.small_objects.medium_strings", {{0, 1}, {0, 32}, {33, 512}, 32}},
    {"shallow_depth.small_objects.large_strings", {{0, 1}, {0, 32}, {513, 1024}, 32}},
    {"shallow_depth.medium_objects.small_strings", {{0, 1}, {33, 128}, {0, 32}, 128}},
    {"shallow_depth.medium_objects.medium_strings", {{0, 1}, {33, 128}, {33, 512}, 128}},
    {"shallow_depth.medium_objects.large_strings", {{0, 1}, {33, 128}, {513, 1024}, 128}},
    {"shallow_depth.large_objects.small_strings", {{0, 1}, {129, 256}, {0, 32}, 512}},
    {"shallow_depth.large_objects.medium_strings", {{0, 1}, {129, 256}, {33, 512}, 512}},
    {"shallow_depth.large_objects.large_strings", {{0, 1}, {129, 256}, {513, 1024}, 512}},
    {"medium_depth.small_objects.small_strings", {{2, 5}, {0, 32}, {0, 32}, 32}},
    {"medium_depth.small_objects.medium_strings", {{2, 5}, {0, 32}, {33, 512}, 32}},
    {"medium_depth.small_objects.large_strings", {{2, 5}, {0, 32}, {513, 1024}, 32}},
    {"medium_depth.medium_objects.small_strings", {{2, 5}, {33, 128}, {0, 32}, 128}},
    {"medium_depth.medium_objects.medium_strings", {{2, 5}, {33, 128}, {33, 512}, 128}},
    {"medium_depth.medium_objects.large_strings", {{2, 5}, {33, 128}, {513, 1024}, 128}},
    {"medium_depth.large_objects.small_strings", {{2, 5}, {129, 256}, {0, 32}, 512}},
    {"medium_depth.large_objects.medium_strings", {{2, 5}, {129, 256}, {33, 512}, 512}},
    {"medium_depth.large_objects.large_strings", {{2, 5}, {129, 256}, {513, 1024}, 512}},
    {"large_depth.small_objects.small_strings", {{6, 20}, {0, 32}, {0, 32}, 32}},
    {"large_depth.small_objects.medium_strings", {{6, 20}, {0, 32}, {33, 512}, 32}},
    {"large_depth.small_objects.large_strings", {{6, 20}, {0, 32}, {513, 1024}, 32}},
    {"large_depth.medium_objects.small_strings", {{6, 20}, {33, 128}, {0, 32}, 128}},
    {"large_depth.medium_objects.medium_strings", {{6, 20}, {33, 128}, {33, 512}, 128}},
    {"large_depth.medium_objects.large_strings", {{6, 20}, {33, 128}, {513, 1024}, 128}},
    {"large_depth.large_objects.small_strings", {{6, 20}, {129, 256}, {0, 32}, 512}},
    {"large_depth.large_objects.medium_strings", {{6, 20}, {129, 256}, {33, 512}, 512}},
    {"large_depth.large_objects.large_strings", {{6, 20}, {129, 256}, {513, 1024}, 512}},
    {"mix", {{0, 20}, {0, 256}, {0, 1024}, 512}},
};

void print_help_and_exit(std::string_view name, std::string_view error = {})
{
    std::cerr << "Usage: " << name << " [OPTION]...\n"
              << "    --rule-file VALUE     Rule file to use on the tests\n"
              << "    --iterations VALUE    Number of iterations per test\n"
              << "    --seed VALUE          Seed for the random number generator\n"
              << "    --format VALUE        Output format: csv, json, human, none\n"
              << "    --list-tests          List all of the available tests\n"
              << "    --test                A comma-separated list of tests to run\n"
              << "    --rtest               A regex matching the tests to run\n"
              << "    --threads VALUE       Number of threads for concurrent testing\n";
              // "                                                                                 "

    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        exit(EXIT_FAILURE);
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

int main(int argc, char *argv[])
{
    auto opts = parse_args(argc, argv);

    //for (auto &[k, v] : opts) {
    //    std::cout << "[" << k << "] = " << v << std::endl;
    //}

    if (contains(opts, "help")) {
        print_help_and_exit(argv[0]);
    }

    std::string_view rule_file;
    if (!contains(opts, "rule-file")) {
        print_help_and_exit(argv[0], "Missing option --rule-file");
    } else {
        rule_file = opts["rule-file"];
    }

    if (contains(opts, "list-tests")) {
        for (auto &[k, v] : default_tests) {
            std::cout << k << std::endl;
        }
        exit(EXIT_SUCCESS);
    }

    benchmark::output_fn_type output_fn = benchmark::output_json;
    if (contains(opts, "format")) {
        auto format = opts["format"];
        if (format == "csv") {
            output_fn = benchmark::output_csv;
        } else if (format == "human") {
            output_fn = benchmark::output_human;
        } else if (format == "json") {
            output_fn = benchmark::output_json;
        } else if (format == "none") {
            output_fn = nullptr;
        } else {
            print_help_and_exit(argv[0], "Unsupported value for --format");
        }
    }

    unsigned iterations = 100;
    if (contains(opts, "iterations")) {
        iterations = atoi(opts["iterations"].data());
        if (iterations == 0) {
            print_help_and_exit(argv[0], "Iterations should be a positive number");
        }
    }

    unsigned seed = 0;
    if (contains(opts, "seed")) {
        seed = atoi(opts["seed"].data());
    } else {
        seed = std::random_device()();
    }
    benchmark::random::seed(seed);

    unsigned threads = 0;
    if (contains(opts, "threads")) {
        threads = atoi(opts["threads"].data());
    }

    std::unordered_set<std::string_view> test_list;
    if (contains(opts, "test")) {
        auto test_str = opts["test"];

        std::size_t delimiter = 0;

        std::string_view remaining = test_str;
        while ((delimiter = remaining.find(',')) != std::string::npos) {
            auto substr = remaining.substr(0, delimiter);
            if (!substr.empty()) {
                test_list.emplace(substr);
            }
            remaining = remaining.substr(delimiter + 1);
        }

        if (!remaining.empty()) {
            test_list.emplace(remaining);
        }

        if (test_list.empty()) {
            std::cerr << "No matching test found" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    if (contains(opts, "rtest")) {
        std::regex test_regex(opts["rtest"].data());
        for (auto &[k, v] : default_tests) {
            if (std::regex_match(k, test_regex)) {
                test_list.emplace(k);
            }
        }

        if (test_list.empty()) {
            std::cerr << "No matching test found" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    ddwaf_object rule = benchmark::rule_parser::from_file(rule_file);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        std::cerr << "Invalid ruleset file" << std::endl;
        exit(EXIT_FAILURE);
    }

    benchmark::runner runner(iterations, threads);
    for (auto &[k, v] : default_tests) {
        if (test_list.empty()) {
            runner.register_fixture<benchmark::run_fixture>(k, iterations, handle, v);
            continue;
        }

        if (test_list.find(k) != test_list.end()) {
            runner.register_fixture<benchmark::run_fixture>(k, iterations, handle, v);
        }
    }
    auto results = runner.run();

    if (output_fn) {
        output_fn(results);
    }

    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
