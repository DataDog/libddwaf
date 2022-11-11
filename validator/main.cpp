// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "assert.hpp"
#include "runner.hpp"
#include "utils.hpp"

const char *level_to_str(DDWAF_LOG_LEVEL level)
{
    switch (level) {
    case DDWAF_LOG_TRACE:
        return "trace";
    case DDWAF_LOG_DEBUG:
        return "debug";
    case DDWAF_LOG_ERROR:
        return "error";
    case DDWAF_LOG_WARN:
        return "warn";
    case DDWAF_LOG_INFO:
        return "info";
    case DDWAF_LOG_OFF:
        break;
    }

    return "off";
}

void log_cb(DDWAF_LOG_LEVEL level, const char *function, const char *file, unsigned line,
    const char *message, [[maybe_unused]] uint64_t len)
{
    printf("[%s][%s:%s:%u]: %s\n", level_to_str(level), file, function, line, message);
}

void print_help_and_exit(std::string_view name, std::string_view error = {})
{
    std::cerr
        << "Usage: " << name << " [OPTION]...\n"
        << "    --tests <FILE>...     Space separated list of test files (default: tests/*.yaml)\n"
        << "    --ruleset VALUE       Test ruleset (default: ruleset.yaml)\n"
        << "    --verbose             Set WAF logging to trace\n"
        << "    --help                Shows this help\n";

    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    std::string ruleset = "ruleset.yaml";
    std::vector<fs::path> files;
    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];
        if (arg == "--verbose") {
            ddwaf_set_log_cb(log_cb, DDWAF_LOG_TRACE);
        } else if (arg == "--tests") {
            while (++i < argc) {
                std::string_view file = argv[i];
                if (file.substr(0, 2) == "--") {
                    --i;
                    break;
                }

                fs::path sample_path = file;
                if (!is_regular_file(sample_path)) {
                    continue;
                }

                if (sample_path.extension() != ".yaml") {
                    continue;
                }

                files.emplace_back(file);
            }

            if (files.empty()) {
                print_help_and_exit(argv[0], "No valid tests provided with --tests");
            }
        } else if (arg == "--ruleset") {
            if (++i < argc) {
                ruleset = argv[i];
                if (ruleset.substr(0, 2) == "--") {
                    print_help_and_exit(argv[0], "No valid ruleset provided with --ruleset");
                }
            } else {
                print_help_and_exit(argv[0], "No valid ruleset provided with --ruleset");
            }
        } else {
            print_help_and_exit(argv[0]);
        }
    }

    if (files.empty()) {
        auto samples = fs::path("tests");
        if (!fs::is_directory(samples)) {
            print_help_and_exit(argv[0], "tests/ not a directory");
            return 0;
        }

        for (auto const &dir_entry : fs::directory_iterator{samples}) {
            fs::path sample_path = dir_entry;
            if (!is_regular_file(sample_path)) {
                continue;
            }
            if (sample_path.extension() != ".yaml") {
                continue;
            }

            files.push_back(dir_entry);
        }
    }

    std::sort(files.begin(), files.end());

    int exit_val = EXIT_SUCCESS;
    test_runner runner(ruleset);
    for (const auto &file : files) {
        auto [res, expected_fail, error, output] = runner.run(file);
        if (res) {
            if (!expected_fail) {
                std::cout << std::string{file} << " => " << term::colour::green << "Passed\n"
                          << term::colour::off;
            } else {
                std::cout << std::string{file} << " => " << term::colour::red
                          << "Expected to fail but passed\n"
                          << term::colour::off;
                exit_val = EXIT_FAILURE;
            }
        } else {
            if (!expected_fail) {
                std::cout << std::string{file} << " => " << term::colour::red << "Failed: " << error
                          << "\n"
                          << term::colour::off;
                if (!output.empty()) {
                    std::cout << output << "\n";
                }
                exit_val = EXIT_FAILURE;
            } else {
                std::cout << std::string{file} << " => " << term::colour::yellow
                          << "Failed (expected): " << error << "\n"
                          << term::colour::off;
            }
        }
    }

    return exit_val;
}
