// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2024 Datadog, Inc.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "action_mapper.hpp"
#include "exclusion/object_filter.hpp"
#include "indexed_multivector.hpp"
#include "indexer.hpp"
#include "processor/base.hpp"
#include "rule.hpp"
#include "scanner.hpp"

namespace ddwaf {

struct rule_spec {
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
    reference_type type;
    std::optional<bool> enabled;
    std::optional<std::vector<std::string>> actions;
    std::vector<reference_spec> targets;
    std::unordered_map<std::string, std::string> tags;
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

enum class processor_type : unsigned {
    extract_schema,
    // Reserved
    http_endpoint_fingerprint,
    http_network_fingerprint,
    http_header_fingerprint,
    session_fingerprint,
};

struct processor_spec {
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
    data_type type{data_type::unknown};
    indexed_multivector<std::string, value_type> values;
};

struct action_spec {
    action_type type;
    std::string type_str;
    std::unordered_map<std::string, std::string> parameters;
};

enum class change_set : uint32_t {
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

constexpr change_set operator|(change_set lhs, change_set rhs)
{
    return static_cast<change_set>(static_cast<std::underlying_type_t<change_set>>(lhs) |
                                   static_cast<std::underlying_type_t<change_set>>(rhs));
}

constexpr change_set operator&(change_set lhs, change_set rhs)
{
    return static_cast<change_set>(static_cast<std::underlying_type_t<change_set>>(lhs) &
                                   static_cast<std::underlying_type_t<change_set>>(rhs));
}

// TODO update this note
// Config spec contains an instance of a parsed configuration. Since this has to
// be composed into a larger configuration, the storage cost need not consider
// retrieval cost.
struct configuration_change_spec {
    [[nodiscard]] bool empty() const { return content == change_set::none; }

    change_set content{change_set::none};

    std::unordered_set<std::string> base_rules;
    std::unordered_set<std::string> user_rules;
    std::vector<std::pair<std::string, std::string>> rule_data;

    std::unordered_set<std::string> overrides_by_id;
    std::unordered_set<std::string> overrides_by_tags;

    std::unordered_set<std::string> rule_filters;
    std::unordered_set<std::string> input_filters;
    std::vector<std::pair<std::string, std::string>> exclusion_data;

    std::unordered_set<std::string> processors;

    std::unordered_set<std::string> scanners;

    std::unordered_set<std::string> actions;
};

struct configuration_spec {
    // Specifies the contents of the configuration
    change_set content{change_set::none};
    // Obtained from 'rules', can't be empty
    std::unordered_map<std::string, rule_spec> base_rules;
    // Obtained from 'custom_rules'
    std::unordered_map<std::string, rule_spec> user_rules;
    // Obtained from 'rules_data', depends on base_rules_
    std::unordered_map<std::string, data_spec> rule_data;
    // Obtained from 'rules_override'
    // The distinction is only necessary due to the restriction that
    // overrides by ID are to be considered a priority over overrides by tags
    std::unordered_map<std::string, override_spec> overrides_by_id;
    std::unordered_map<std::string, override_spec> overrides_by_tags;
    // Obtained from 'exclusions'
    std::unordered_map<std::string, rule_filter_spec> rule_filters;
    std::unordered_map<std::string, input_filter_spec> input_filters;
    // Obtained from 'exclusion_data', depends on exclusions_
    std::unordered_map<std::string, data_spec> exclusion_data;
    // Obtained from 'processors'
    std::unordered_map<std::string, processor_spec> processors;
    // Scanner container
    indexer<const scanner> scanners;
    // Actions
    std::unordered_map<std::string, action_spec> actions;
};

} // namespace ddwaf
