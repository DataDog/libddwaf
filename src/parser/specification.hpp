// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>

#include "exception.hpp"
#include "exclusion/object_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "expression.hpp"
#include "parameter.hpp"
#include "processor/base.hpp"
#include "rule.hpp"
#include "scanner.hpp"

namespace ddwaf::parser {

struct rule_spec {
    bool enabled;
    rule::source_type source;
    std::string name;
    std::unordered_map<std::string, std::string> tags;
    std::shared_ptr<expression> expr;
    std::vector<std::string> actions;
};

enum class reference_type { none, id, tags };

struct reference_spec {
    reference_type type;
    std::string ref_id;
    std::unordered_map<std::string, std::string> tags;
};

struct override_spec {
    std::optional<bool> enabled;
    std::optional<std::vector<std::string>> actions;
    std::vector<reference_spec> targets;
};

struct rule_filter_spec {
    std::shared_ptr<expression> expr;
    std::vector<reference_spec> targets;
    exclusion::filter_mode on_match;
    std::string custom_action;
};

struct input_filter_spec {
    std::shared_ptr<expression> expr;
    std::shared_ptr<exclusion::object_filter> filter;
    std::vector<reference_spec> targets;
};

// Containers
using rule_spec_container = std::unordered_map<std::string, rule_spec>;
using matcher_container = std::unordered_map<std::string, std::shared_ptr<matcher::base>>;
using scanner_container = std::unordered_map<std::string_view, std::shared_ptr<scanner>>;

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
