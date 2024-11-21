// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "module.hpp"
#include "module_category.hpp"
#include "rule.hpp"

namespace ddwaf {

// The module builder can be used to build a single module
class rule_module_builder {
public:
    using source_type = core_rule::source_type;
    using source_precedence_fn_type = bool (*)(source_type left, source_type right);
    using grouping_key_fn_type = std::string_view (*)(const core_rule *rule);

    rule_module_builder(
        source_precedence_fn_type source_precedence, grouping_key_fn_type grouping_key)
        : source_precedence_fn_(source_precedence), grouping_key_fn_(grouping_key)
    {}
    ~rule_module_builder() = default;
    rule_module_builder(rule_module_builder &&) = delete;
    rule_module_builder(const rule_module_builder &) = delete;
    rule_module_builder &operator=(rule_module_builder &&) = delete;
    rule_module_builder &operator=(const rule_module_builder &) = delete;

    void insert(core_rule *rule) { rules_.emplace_back(rule); }

    rule_module build();

protected:
    source_precedence_fn_type source_precedence_fn_;
    grouping_key_fn_type grouping_key_fn_;
    std::vector<core_rule *> rules_;
    std::vector<rule_module::rule_collection> collections_;
};

// Modules:
//   - Network-ACL:
//      - Order:
//          blocking
//          non-blocking
//      - Short-circuit: rule match
//      - No timing
//   - Authentication-ACL:
//      - Order:
//          blocking
//          non-blocking
//      - Short-circuit: rule match
//      - No timing
//   - Custom-ACL:
//      - Order:
//          blocking user rules
//          blocking datadog rules
//          non-blocking user
//          non-blocking datadog rules
//      - Short-circuit: rule match
//      - Timed
//   - Configuration:
//      - Order:
//          blocking user rules
//          blocking datadog rules
//          non-blocking user
//          non-blocking datadog rules
//      - Short-circuit: rule match
//      - Timed
//   - Business logic:
//      - Order:
//          blocking user rules
//          blocking datadog rules
//          non-blocking user
//          non-blocking datadog rules
//      - Short-circuit: rule match
//      - Timed
//   - RASP:
//      - Order:
//          blocking datadog rules
//          blocking user rules
//          non-blocking datadog rules
//          non-blocking user
//      - Short-circuit: rule match
//      - Timed
//   - WAF:
//      - Order:
//          blocking datadog rules
//          blocking user rules
//          non-blocking datadog rules
//          non-blocking user
//      - Short-circuit: rule match, but only rules of the same type (collections)
//      - Timed

class rule_module_set_builder {
public:
    rule_module_set_builder() = default;
    ~rule_module_set_builder() = default;
    rule_module_set_builder(rule_module_set_builder &&) = delete;
    rule_module_set_builder(const rule_module_set_builder &) = delete;
    rule_module_set_builder &operator=(rule_module_set_builder &&) = delete;
    rule_module_set_builder &operator=(const rule_module_set_builder &) = delete;

    std::array<rule_module, rule_module_count> build(
        const std::vector<std::shared_ptr<core_rule>> &base,
        const std::vector<std::shared_ptr<core_rule>> &user);

protected:
    // Helpers
    static bool user_rule_precedence(
        const core_rule::source_type left, const core_rule::source_type right)
    {
        return left > right;
    }

    static bool base_rule_precedence(
        const core_rule::source_type left, const core_rule::source_type right)
    {
        return left < right;
    }

    static std::string_view type_grouping_key(const core_rule *rule) { return rule->get_type(); }
    static constexpr std::string_view null_grouping_key(const core_rule * /*rule*/) { return {}; }

    std::array<rule_module_builder, rule_module_count> builders_{{
        {base_rule_precedence, null_grouping_key}, // Network-ACL
        {base_rule_precedence, null_grouping_key}, // Authentication-ACL
        {user_rule_precedence, null_grouping_key}, // Custom-ACL
        {user_rule_precedence, null_grouping_key}, // Configuration
        {user_rule_precedence, null_grouping_key}, // Business logic
        {base_rule_precedence, null_grouping_key}, // RASP
        {user_rule_precedence, type_grouping_key}, // WAF
    }};
};

} // namespace ddwaf
