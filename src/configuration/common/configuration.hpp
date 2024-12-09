// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2024 Datadog, Inc.

// Unless explicitly setd otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "exclusion/object_filter.hpp"
#include "processor/base.hpp"
#include "rule.hpp"
#include "scanner.hpp"

namespace ddwaf {

struct rule_spec {
    std::string id;
    bool enabled;
    core_rule::source_type source;
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
    std::unordered_map<std::string, std::string> tags;
};

struct rule_filter_spec {
    std::string id;
    std::shared_ptr<expression> expr;
    std::vector<reference_spec> targets;
    exclusion::filter_mode on_match;
    std::string custom_action;
};

struct input_filter_spec {
    std::string id;
    std::shared_ptr<expression> expr;
    std::shared_ptr<exclusion::object_filter> filter;
    std::vector<reference_spec> targets;
};

enum class processor_type : unsigned {
    extract_schema,
    // Reserved
    http_endpoint_fingerprint,
    http_network_fingerprint,
    http_header_fingerprint,
    session_fingerprint,
};

struct processor_spec {
    std::string id;
    processor_type type;
    std::shared_ptr<expression> expr;
    std::vector<processor_mapping> mappings;
    std::vector<reference_spec> scanners;
    bool evaluate{false};
    bool output{true};
};

enum class data_type { unknown, data_with_expiration, ip_with_expiration };

struct data_spec {
    using value_type = std::pair<std::string, uint64_t>;
    std::string id;
    data_type type;
    std::vector<value_type> values;
};

// Config spec contains an instance of a parsed configuration. Since this has to
// be composed into a larger configuration, the storage cost need not consider
// retrieval cost.
struct configuration_spec {
    enum class content_set : uint32_t {
        none = 0,
        rules = 1,
        custom_rules = 2,
        overrides = 4,
        filters = 8,
        rule_data = 16,
        processors = 32,
        scanners = 64,
        actions = 128,
        exclusion_data = 256,
    };

    friend constexpr content_set operator|(content_set lhs, content_set rhs);
    friend constexpr content_set operator&(content_set lhs, content_set rhs);

    [[nodiscard]] bool empty() const { return content == content_set::none; }

    // Specifies the contents of the configuration
    content_set content;

    // Obtained from 'rules', can't be empty
    std::vector<rule_spec> base_rules;
    // Obtained from 'custom_rules'
    std::vector<rule_spec> user_rules;
    // Obtained from 'rules_data', depends on base_rules_
    std::vector<data_spec> rule_data;
    // Obtained from 'rules_override'
    // The distinction is only necessary due to the restriction that
    // overrides by ID are to be considered a priority over overrides by tags
    std::vector<override_spec> overrides_by_id;
    std::vector<override_spec> overrides_by_tags;
    // Obtained from 'exclusions'
    std::vector<rule_filter_spec> rule_filters;
    std::vector<input_filter_spec> input_filters;
    // Obtained from 'exclusion_data', depends on exclusions_
    std::vector<data_spec> exclusion_data;
    // Obtained from 'processors'
    std::vector<processor_spec> processors;
    // Scanner container
    std::vector<std::shared_ptr<scanner>> scanners;
    // Actions
    std::shared_ptr<action_mapper> actions;
};

struct spec_id_tracker {
    std::unordered_set<std::string> rules;
    std::unordered_set<std::string> filters;
    std::unordered_set<std::string> processors;
    std::unordered_set<std::string> scanners;
};

constexpr configuration_spec::content_set operator|(
    configuration_spec::content_set lhs, configuration_spec::content_set rhs)
{
    return static_cast<configuration_spec::content_set>(
        static_cast<std::underlying_type_t<configuration_spec::content_set>>(lhs) |
        static_cast<std::underlying_type_t<configuration_spec::content_set>>(rhs));
}

constexpr configuration_spec::content_set operator&(
    configuration_spec::content_set lhs, configuration_spec::content_set rhs)
{
    return static_cast<configuration_spec::content_set>(
        static_cast<std::underlying_type_t<configuration_spec::content_set>>(lhs) &
        static_cast<std::underlying_type_t<configuration_spec::content_set>>(rhs));
}

} // namespace ddwaf
