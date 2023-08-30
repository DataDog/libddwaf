// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "exclusion/rule_filter.hpp"
#include <exception.hpp>
#include <exclusion/object_filter.hpp>
#include <expression.hpp>
#include <parameter.hpp>
#include <processor.hpp>
#include <rule.hpp>
#include <scanner.hpp>

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

struct reference_target_spec {
    target_type type;
    std::string rule_id;
    std::unordered_map<std::string, std::string> tags;
};

struct override_spec {
    std::optional<bool> enabled;
    std::optional<std::vector<std::string>> actions;
    std::vector<reference_target_spec> targets;
};

struct rule_filter_spec {
    expression::ptr expr;
    std::vector<reference_target_spec> targets;
    exclusion::filter_mode on_match;
};

struct input_filter_spec {
    expression::ptr expr;
    std::shared_ptr<exclusion::object_filter> filter;
    std::vector<reference_target_spec> targets;
};

// Containers
using rule_spec_container = std::unordered_map<std::string, rule_spec>;
using rule_data_container = std::unordered_map<std::string, matcher::base::shared_ptr>;
using scanner_container = std::unordered_map<std::string_view, scanner::ptr>;

struct processor_container {
    [[nodiscard]] bool empty() const { return pre.empty() && post.empty(); }
    [[nodiscard]] std::size_t size() const { return pre.size() + post.size(); }
    void clear()
    {
        pre.clear();
        post.clear();
    }

    std::unordered_map<std::string_view, processor::ptr> pre;
    std::unordered_map<std::string_view, processor::ptr> post;
};

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
