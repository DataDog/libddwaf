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

void log_cb(DDWAF_LOG_LEVEL level, const char *function, const char *file,
    unsigned line, const char *message, [[maybe_unused]] uint64_t len)
{
    printf("[%s][%s:%s:%u]: %s\n", level_to_str(level), file, function, line,
        message);
}

int main(int argc, char *argv[])
{
    std::vector<fs::path> files;
    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];
        if (arg == "--verbose") {
            ddwaf_set_log_cb(log_cb, DDWAF_LOG_TRACE);
            continue;
        }

        fs::path sample_path = arg;
        if (!is_regular_file(sample_path)) {
            std::cout << arg << " not a regular file\n";
            continue;
        }

        if (sample_path.extension() != ".yaml") {
            std::cout << arg << " not a YAML file (?)\n";
            continue;
        }

        files.emplace_back(arg);
    }

    if (files.empty()) {
        auto samples = fs::path("tests");
        if (!fs::is_directory(samples)) {
            std::cerr << samples << " not a directory\n";
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

    int exit_val = 0;
    test_runner runner("ruleset.yaml");
    for (const auto &file : files) {
        auto [res, expected_fail, error, output] = runner.run(file);
        if (res) {
            if (!expected_fail) {
                std::cout << std::string{file} << " => " << term::colour::green
                          << "Passed\n"
                          << term::colour::off;
            } else {
                std::cout << std::string{file} << " => " << term::colour::red
                          << "Expected to fail but passed\n"
                          << term::colour::off;
                exit_val = 1;
            }
        } else {
            if (!expected_fail) {
                std::cout << std::string{file} << " => " << term::colour::red
                          << "Failed: " << error << "\n"
                          << term::colour::off << output << "\n";
                exit_val = 1;
            } else {
                std::cout << std::string{file} << " => " << term::colour::yellow
                          << "Failed (expected): " << error << "\n"
                          << term::colour::off;
            }
        }
    }

    return exit_val;
}
