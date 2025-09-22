// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.

#pragma once

#include <filesystem>
#include <sstream>
#include <string>
#include <tuple>
#include <yaml-cpp/yaml.h>

#include "ddwaf.h"

namespace fs = std::filesystem;

class test_runner {
public:
    using result = std::tuple<bool, bool, std::string, std::string>;
    explicit test_runner(const std::string &rule_file);

    test_runner(const test_runner &) = delete;
    test_runner(test_runner &&) = delete;

    test_runner &operator=(const test_runner &) = delete;
    test_runner &operator=(test_runner &&) = delete;

    ~test_runner();

    result run(const fs::path &sample_file);

protected:
    bool run_test(const YAML::Node &runs);
    bool run_self_test(const YAML::Node &runs);

    void validate(const YAML::Node &expected, const YAML::Node &obtained);
    static void validate_rule(const YAML::Node &expected, const YAML::Node &obtained);
    static void validate_conditions(const YAML::Node &expected, const YAML::Node &obtained);
    static void validate_matches(const YAML::Node &expected, const YAML::Node &obtained);
    static void validate_actions(const YAML::Node &expected, const YAML::Node &obtained);
    static void validate_action_params(const YAML::Node &expected, const YAML::Node &obtained);
    static void validate_attributes(const YAML::Node &expected, const YAML::Node &obtained);
    static void validate_equals(const YAML::Node &expected, const YAML::Node &obtained);

    static constexpr unsigned timeout = 1000000;
    ddwaf_handle handle_;
    std::map<std::string, YAML::Node> rules_;
    std::map<std::string, YAML::Node> custom_rules_;
    std::stringstream output_;
    std::stringstream error_;
};
