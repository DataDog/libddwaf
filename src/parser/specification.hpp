// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <condition.hpp>
#include <exception.hpp>
#include <exclusion/object_filter.hpp>
#include <parameter.hpp>
#include <rule.hpp>

#include <string>

namespace ddwaf::parser {

struct rule_spec {
    bool enabled;
    rule::source_type source;
    std::string name;
    std::unordered_map<std::string, std::string> tags;
    expression::ptr expr;
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
    std::optional<std::vector<std::string>> actions;
    std::vector<rule_target_spec> targets;
};

// Filter conditions don't need to be regenerated, so we don't need to use
// the condition_spec
struct rule_filter_spec {
    std::vector<condition::ptr> conditions;
    std::vector<rule_target_spec> targets;
};

struct input_filter_spec {
    std::vector<condition::ptr> conditions;
    std::shared_ptr<exclusion::object_filter> filter;
    std::vector<rule_target_spec> targets;
};

// Containers
using rule_spec_container = std::unordered_map<std::string, rule_spec>;
using rule_data_container = std::unordered_map<std::string, rule_processor::base::ptr>;

struct override_spec_container {
    [[nodiscard]] bool empty() const { return by_ids.empty() && by_tags.empty(); }
    void clear()
    {
        by_ids.clear();
        by_tags.clear();
    }
    // The distinction is only necessary due to the restriction that
    // overrides by ID are to be considered a priority over overrides by tags
    std::vector<override_spec> by_ids;
    std::vector<override_spec> by_tags;
};

struct filter_spec_container {
    [[nodiscard]] bool empty() const { return rule_filters.empty() && input_filters.empty(); }

    void clear()
    {
        rule_filters.clear();
        input_filters.clear();
    }

    std::unordered_set<std::string> ids;
    std::unordered_map<std::string, rule_filter_spec> rule_filters;
    std::unordered_map<std::string, input_filter_spec> input_filters;
};

} // namespace ddwaf::parser
