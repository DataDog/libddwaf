// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <exception.hpp>
#include <exclusion/input_filter.hpp>
#include <exclusion/rule_filter.hpp>
#include <parameter.hpp>
#include <rule.hpp>

#include <string>

namespace ddwaf::parser {

struct rule_spec {
    bool enabled;
    std::string name;
    std::unordered_map<std::string, std::string> tags;
    std::vector<condition::ptr> conditions;
    std::vector<std::string> actions;
};

enum class target_type { none, id, tags };

struct rule_target_spec {
    target_type type;
    std::string rule_id;
    std::unordered_map<std::string, std::string> tags;
};

struct override_spec {
    std::optional<bool> enabled;
    std::vector<std::string> actions;
    std::vector<rule_target_spec> targets;
};

struct rule_filter_spec {
    std::vector<condition::ptr> conditions;
    std::vector<rule_target_spec> targets;
};

struct input_filter_spec {
    std::vector<condition::ptr> conditions;
    ddwaf::exclusion::object_filter filter;
    std::vector<rule_target_spec> targets;
};

// Containers
using rule_spec_container = std::unordered_map<std::string, rule_spec>;

struct override_spec_container {
    // The distinction is only necessary due to the restriction that
    // overrides by ID are to be considered a priority over overrides by tags
    std::vector<override_spec> by_ids;
    std::vector<override_spec> by_tags;
};

struct filter_spec_container {
    std::unordered_map<std::string, rule_filter_spec> unconditional_rule_filters;
    std::unordered_map<std::string, rule_filter_spec> rule_filters;
    std::unordered_map<std::string, input_filter_spec> input_filters;
};

// TODO include rule_data?

} // namespace ddwaf::parser
