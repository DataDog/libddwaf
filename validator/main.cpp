// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "assert.hpp"
#include "runner.hpp"
#include "utils.hpp"

namespace {
constexpr unsigned max_dir_depth = 4;
}

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
    std::cerr << "Usage: " << name << " [OPTION]...\n"
              << "    --tests <FILE|DIR>... Space separated list of test files or directories "
                 "(default: tests/)\n"
              << "    --verbose             Set WAF logging to trace\n"
              << "    --help                Shows this help\n";

    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

auto add_dir(const fs::path &dir, std::map<fs::path, std::vector<fs::path>> &files)
{
    auto it = files.find(dir);
    if (it != files.end()) {
        return it;
    }

    fs::path ruleset = dir / "ruleset.yaml";
    if (!is_regular_file(ruleset)) {
        return files.end();
    }

    auto [new_it, res] = files.emplace(dir, std::vector<fs::path>{});
    return res ? new_it : files.end();
}

// NOLINTNEXTLINE(misc-no-recursion)
void extract_all_files(
    const fs::path &dir, std::map<fs::path, std::vector<fs::path>> &files, unsigned level = 0)
{
    if (level == max_dir_depth) {
        return;
    }

    auto it = add_dir(dir, files);
    if (it == files.end()) {
        // If there's not ruleset, we just iterate through further directories
        for (auto const &dir_entry : fs::directory_iterator{dir}) {
            const fs::path &new_dir = dir_entry;
            if (is_directory(new_dir)) {
                extract_all_files(new_dir, files, level + 1);
            }
        }
        return;
    }

    std::vector<fs::path> &tests = it->second;

    for (auto const &dir_entry : fs::directory_iterator{dir}) {
        const fs::path &sample_path = dir_entry;

        if (sample_path.filename() == "ruleset.yaml") {
            continue;
        }

        if (is_regular_file(sample_path) && sample_path.extension() == ".yaml") {
            tests.push_back(sample_path);
        } else if (is_directory(sample_path)) {
            extract_all_files(sample_path, files, level + 1);
        }
    }
}

bool run_tests(const std::string &ruleset, const std::vector<fs::path> &files)
{
    unsigned passed = 0;
    unsigned xpassed = 0;
    unsigned failed = 0;
    unsigned xfailed = 0;

    test_runner runner(ruleset);
    for (const auto &file : files) {
        auto [res, expected_fail, error, output] = runner.run(file);
        if (res) {
            if (!expected_fail) {
                std::cout << std::string{file} << " => " << term::colour::green << "Passed\n"
                          << term::colour::off;
                ++passed;
            } else {
                std::cout << std::string{file} << " => " << term::colour::red
                          << "Expected to fail but passed\n"
                          << term::colour::off;
                ++xpassed;
            }
        } else {
            if (!expected_fail) {
                std::cout << std::string{file} << " => " << term::colour::red << "Failed: " << error
                          << "\n"
                          << term::colour::off;
                if (!output.empty()) {
                    std::cout << output << "\n";
                }
                ++failed;
            } else {
                std::cout << std::string{file} << " => " << term::colour::yellow
                          << "Failed (expected): " << error << "\n"
                          << term::colour::off;
                ++xfailed;
            }
        }
    }

    std::cout << term::colour::blue << "Result: " << term::colour::white << files.size() << " tests"
              << term::colour::off;
    if (failed > 0) {
        std::cout << ", " << term::colour::red << failed << " failed" << term::colour::off;
    }

    std::cout << ", " << term::colour::green << passed << " passed" << term::colour::off;

    if (xfailed > 0) {
        std::cout << ", " << term::colour::yellow << xfailed << " xfailed" << term::colour::off;
    }

    if (xpassed > 0) {
        std::cout << ", " << term::colour::magenta << xpassed << " xpassed" << term::colour::off;
    }
    std::cout << '\n';

    return failed == 0 && xpassed == 0;
}

int main(int argc, char *argv[])
{
    std::map<fs::path, std::vector<fs::path>> files;
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
                if (is_directory(sample_path)) {
                    extract_all_files(sample_path, files);
                } else if (is_regular_file(sample_path)) {
                    if (sample_path.extension() != ".yaml") {
                        continue;
                    }

                    auto it = add_dir(sample_path.root_directory(), files);
                    if (it == files.end()) {
                        continue;
                    }

                    it->second.emplace_back(sample_path);
                } else {
                    continue;
                }
            }

            if (files.empty()) {
                print_help_and_exit(argv[0], "No valid tests provided with --tests");
            }
        } else {
            print_help_and_exit(argv[0]);
        }
    }

    if (files.empty()) {
        extract_all_files(fs::path("tests"), files);
    }

    int exit_val = EXIT_SUCCESS;

    for (auto &[dir, tests] : files) {
        if (tests.empty()) {
            continue;
        }

        std::sort(tests.begin(), tests.end());

        std::cout << term::colour::cyan << "Testing: " << std::string(dir) << term::colour::off
                  << '\n';
        if (!run_tests(dir / "ruleset.yaml", tests)) {
            exit_val = EXIT_FAILURE;
        }

        if (files.rbegin()->first != dir) {
            std::cout << '\n';
        }
    }

    if (exit_val == EXIT_SUCCESS) {
        std::cout << term::colour::green << "\nValidation succeeded\n";
    } else {
        std::cout << term::colour::red << "\nValidation failed\n";
    }
    return exit_val;
}
