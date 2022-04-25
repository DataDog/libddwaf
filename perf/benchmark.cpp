// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <string_view>
#include <utility>
#include <vector>

#include <ddwaf.h>
#include "object_generator.hpp"
#include "output_formatter.hpp"
#include "random.hpp"
#include "rule_parser.hpp"
#include "runner.hpp"
#include "run_fixture.hpp"

using namespace ddwaf;


void print_help(char *name)
{
    std::cerr << "Usage: " << name << " [OPTION]...\n"
              << "    --rule-file VALUE     Rule file to use on the tests\n"
              << "    --iterations VALUE    Number of iterations per test\n"
              << "    --seed VALUE          Seed for the random number generator\n"
              << "    --format VALUE        Output format: csv, json, human\n"
              << "    --randomize-cache     [Experimental] Attempt to randomize the cache between\n"
              << "                          each iteration, this is quite slow\n"
              << "                                                                                 \n";
}

std::map<std::string_view, std::string_view> parse_args(int argc, char *argv[])
{
    std::map<std::string_view, std::string_view> parsed_args;

    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];
        if (arg.substr(0, 2) != "--") {
            continue;
        }

        std::string_view opt_name = arg.substr(2);
        parsed_args[opt_name] = {};

        if ((i + 1) < argc) {
            std::string_view value = argv[i + 1];
            if (value.substr(0, 2) != "--") {
                parsed_args[opt_name] = value;
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

/*    for (auto &[k, v] : opts) {*/
        //std::cout << "[" << k << "] = " << v << std::endl;
    //}

    if (contains(opts, "help")) {
        print_help(argv[0]);
        exit(EXIT_SUCCESS);
    }

    std::string_view rule_file;
    if (!contains(opts, "rule-file")) {
        print_help(argv[0]);
        std::cerr << "Missing option --rule-file\n";
        exit(EXIT_FAILURE);
    } else {
        rule_file = opts["rule-file"];
    }

    benchmark::output_fn_type output_fn = benchmark::output_human;
    if (contains(opts, "format")) {
        auto format = opts["format"];
        if (format == "csv") {
            output_fn = benchmark::output_csv;
        } else if (format == "json") {
            output_fn = benchmark::output_json;
        }
    }

    unsigned iterations = 100;
    if (contains(opts, "iterations")) {
        iterations = atoi(opts["iterations"].data());
    }

    unsigned seed = 0;
    if (contains(opts, "seed")) {
        seed = atoi(opts["seed"].data());
    } else {
        seed = std::random_device()();
        //std::cout << "Seed: " << seed << std::endl;
    }
    benchmark::random::seed(seed);

    benchmark::runner runner;

    runner.register_fixture<benchmark::run_fixture>(
        "single_depth_small_objects_small_strings", iterations, rule_file,
        benchmark::object_generator::limits{{0, 1}, {0, 32}, {0, 32}});

    runner.register_fixture<benchmark::run_fixture>(
        "single_depth_small_objects_medium_strings", iterations, rule_file,
        benchmark::object_generator::limits{{0, 1}, {0, 32}, {32, 512}});

    runner.register_fixture<benchmark::run_fixture>(
        "single_depth_small_objects_large_strings", iterations, rule_file,
        benchmark::object_generator::limits{{0, 1}, {0, 32}, {512, 4096}});

    runner.register_fixture<benchmark::run_fixture>(
        "single_depth_medium_objects_small_strings", iterations, rule_file,
        benchmark::object_generator::limits{{0, 1}, {32, 128}, {0, 32}});

    runner.register_fixture<benchmark::run_fixture>(
        "single_depth_medium_objects_medium_strings", iterations, rule_file,
        benchmark::object_generator::limits{{0, 1}, {32, 128}, {32, 512}});

    //runner.register_fixture<benchmark::run_fixture>(
        //"single_depth_medium_objects_large_strings", iterations, rule_file,
        //benchmark::object_generator::limits{{0, 1}, {32, 128}, {512, 4096}});

/*    runner.register_fixture<benchmark::run_fixture>(*/
        //"medium_depth_small_objects_small_strings", iterations, rule_file,
        //benchmark::object_generator::limits{{1, 5}, {0, 32}, {0, 32}});

    //runner.register_fixture<benchmark::run_fixture>(
        //"medium_depth_small_objects_medium_strings", iterations, rule_file,
        //benchmark::object_generator::limits{{1, 5}, {0, 32}, {32, 512}});

    //runner.register_fixture<benchmark::run_fixture>(
        //"medium_depth_small_objects_large_strings", iterations, rule_file,
        /*benchmark::object_generator::limits{{1, 5}, {0, 32}, {512, 4096}});*/

    //runner.register_fixture<benchmark::run_fixture>(
        //"medium_depth_medium_objects_small_strings", iterations, rule_file,
        //benchmark::object_generator::limits{{1, 5}, {32, 128}, {0, 32}});

    //runner.register_fixture<benchmark::run_fixture>(
        //"medium_depth_medium_objects_medium_strings", iterations, rule_file,
        //benchmark::object_generator::limits{{1, 5}, {32, 128}, {32, 512}});

    //runner.register_fixture<benchmark::run_fixture>(
        //"medium_depth_medium_objects_large_strings", iterations, rule_file,
        //benchmark::object_generator::limits{{1, 5}, {32, 128}, {512, 4096}});

    auto results = runner.run();

    output_fn(results);
    return EXIT_SUCCESS;
}
