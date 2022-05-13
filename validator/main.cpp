// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

#include "assert.hpp"
#include "utils.hpp"

#define LONG_TIME 1000000

const char* level_to_str(DDWAF_LOG_LEVEL level)
{
    switch (level)
    {
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

void log_cb(DDWAF_LOG_LEVEL level,
            const char* function, const char* file, unsigned line,
            const char* message, uint64_t)
{
    printf("[%s][%s:%s:%u]: %s\n", level_to_str(level), file, function, line, message);
}

void validate_tags(const YAML::Node &matched, const YAML::Node &rule)
{
    expect_yaml(std::string, matched, rule, "type");
    expect_yaml(std::string, matched, rule, "category");
}

void validate_rule(const YAML::Node &matched, const YAML::Node &rule)
{
    expect_yaml(int, matched, rule, "id");
    expect_yaml(std::string, matched, rule, "name");
    validate_tags(matched["tags"], rule["tags"]);
}

void validate_match(const YAML::Node &expected, const YAML::Node &result)
{
    if (expected["address"].IsDefined()) {
        expect_yaml(std::string, expected, result, "address");
    }
    if (expected["key_path"].IsDefined()) {
        expect_yaml(std::vector<std::string>, expected, result, "key_path");
    }
    expect_yaml(std::string, expected, result, "value");
}

void validate_cond_matches(const YAML::Node &conds, const YAML::Node &expected, const YAML::Node &result)
{
    // Iterate through matches, assume they are in the same order as rule
    // conditions for now.
    for (std::size_t i = 0; i < expected.size(); i++) {
        auto cond = conds[i];
        auto cond_match = result[i];
        auto expected_match = expected[i];

        expect_yaml(std::string, cond, cond_match, "operator");

        auto op = cond["operator"].as<std::string>();
        if (op == "match_regex") {
            auto regex = cond["parameters"]["regex"].as<std::string>();
            expect(regex, cond_match["operator_value"].as<std::string>());
        }

        validate_match(expected_match, cond_match["parameters"][0]);
    }
}

void validate(std::map<std::string, YAML::Node> &rules, const YAML::Node &expected, const YAML::Node &result)
{
    expect(expected.size(), result.size());

    bool found_expected = false;
    for (std::size_t i = 0; i < expected.size(); i++) {
        auto expected_rule_matches = expected[i];

        for (std::size_t j = 0; j < result.size(); j++) {
            auto rule_match = result[j];
            auto id = rule_match["rule"]["id"].as<std::string>();

            auto expected_rule_match = expected_rule_matches[id];
            if (!expected_rule_match.IsDefined()) {
                continue;
            }

            found_expected = true;

            auto rule = rules[id];
            validate_rule(rule_match["rule"], rule);

            auto conds = rule["conditions"];
            auto cond_matches = rule_match["rule_matches"];

            expect(conds.size(), cond_matches.size());
            expect(conds.size(), expected_rule_match.size());

            validate_cond_matches(conds, expected_rule_match, cond_matches);

            break;
        }

        expect(found_expected, true);
    }
}

void run_sample(ddwaf_handle handle, std::map<std::string, YAML::Node> &rules,
    YAML::Node &sample)
{
    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);

    auto runs = sample["runs"];
    for (auto it = runs.begin(); it != runs.end(); ++it) {
        YAML::Node run = *it;
        DDWAF_RET_CODE code = DDWAF_GOOD;
        if (run["code"].as<std::string>() == "monitor") { code = DDWAF_MONITOR; }

        auto object = run["input"].as<ddwaf_object>();

        ddwaf_result res;
        auto retval = ddwaf_run(context, &object, &res, LONG_TIME);

        try {
            expect(retval, code);
            if (code == DDWAF_MONITOR) {
                YAML::Node result = YAML::Load(res.data);
                validate(rules, run["rules"], result);
            }
        } catch (...) {
            if (res.data != nullptr) {
                std::cout << YAML::Load(res.data) << std::endl;
            }

            ddwaf_result_free(&res);
            ddwaf_context_destroy(context);
            throw;
        }

        ddwaf_result_free(&res);
    }

    ddwaf_context_destroy(context);
}

int main(int argc, char *argv[])
{
    std::string rule_str = read_rule_file("ruleset.yaml");
    YAML::Node doc       = YAML::Load(rule_str);

    ddwaf_object rule   = doc.as<ddwaf_object>();
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        exit(EXIT_FAILURE);
    }

    std::map<std::string, YAML::Node> rule_map;
    auto rules = doc["rules"];
    for (auto it = rules.begin(); it != rules.end(); ++it) {
        YAML::Node rule = *it;
        auto id = rule["id"].as<std::string>();
        rule_map[id] = rule;
    }

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

        files.push_back(arg);
    }

    if (files.empty()) {
        auto samples = fs::path("tests");
        if (!fs::is_directory(samples)) {
            std::cerr << samples << " not a directory\n";
            return 0;
        }

        for (auto const& dir_entry : fs::directory_iterator{samples}) {
            fs::path sample_path = dir_entry;
            if (!is_regular_file(sample_path)) { continue; }
            if (sample_path.extension() != ".yaml") { continue; }

            files.push_back(dir_entry);
        }
    }


    std::sort(files.begin(), files.end());

    for (const auto &file: files) {
        try {
            std::cout << "Running " << std::string{file} << std::endl;
            std::string sample_str = read_rule_file(file.c_str());
            YAML::Node sample = YAML::Load(sample_str);
            run_sample(handle, rule_map, sample);
            std::cout << "Result => Passed\n";
        } catch (const std::exception &e) {
            std::cout << "Result => Failed: " << e.what() << "\n";
        }
    }

    ddwaf_destroy(handle);

    return 0;
}
