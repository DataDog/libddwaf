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

// Helpers
inline bool user_rule_precedence(
    const core_rule::source_type left, const core_rule::source_type right)
{
    return left > right;
}

inline bool base_rule_precedence(
    const core_rule::source_type left, const core_rule::source_type right)
{
    return left < right;
}

[[gnu::const]] inline std::string_view type_grouping_key(const core_rule *rule)
{
    return rule->get_type();
}
[[gnu::const]] constexpr std::string_view null_grouping_key(const core_rule * /*rule*/)
{
    return {};
}

// The module builder can be used to build a single module
class rule_module_builder {
public:
    using source_type = core_rule::source_type;
    using source_precedence_fn_type = bool (*)(source_type left, source_type right);
    using grouping_key_fn_type = std::string_view (*)(const core_rule *rule);
    using expiration_policy = rule_module::expiration_policy;

    rule_module_builder(source_precedence_fn_type source_precedence,
        grouping_key_fn_type grouping_key, expiration_policy policy = expiration_policy::expiring)
        : source_precedence_fn_(source_precedence), grouping_key_fn_(grouping_key), policy_(policy)
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
    expiration_policy policy_;
};

class rule_module_set_builder {
public:
    rule_module_set_builder() = default;
    ~rule_module_set_builder() = default;
    rule_module_set_builder(rule_module_set_builder &&) = delete;
    rule_module_set_builder(const rule_module_set_builder &) = delete;
    rule_module_set_builder &operator=(rule_module_set_builder &&) = delete;
    rule_module_set_builder &operator=(const rule_module_set_builder &) = delete;

    std::array<rule_module, rule_module_count> build(
        const std::vector<std::shared_ptr<core_rule>> &rules);

protected:
    /* Rules Ordering
     * ---------------------------
     * network_acl: (ignore timeout)
     *  - Collection: [order by: verdict (block then monitor), source (base then user)]
     *
     * authentication_acl: (ignore timeout)
     *  - Collection: [order by: verdict, source (base then user)]
     *
     * custom_acl:
     *   - Collection: [order by: verdict, source (user then base)]
     *
     * configuration:
     *   - Collection: [order by: verdict, source (user then base)]
     *
     * business_logic:
     *   - Collection: [order by: verdict, source (user then base)]
     *
     * rasp:
     *   - Collection: [order by: verdict, source (base then user)]
     *
     * waf:
     *   - Collection: [verdict=block, source=user, type=<type 1>]
     *   - Collection: [verdict=block, source=user, type=...]
     *   - Collection: [verdict=block, source=base, type=<type 1>]
     *   - Collection: [verdict=block, source=base, type=...]
     *   - Collection: [verdict=monitor, source=user, type=<type 1>]
     *   - Collection: [verdict=monitor, source=user, type=...]
     *   - Collection: [verdict=monitor, source=base, type=<type 1>]
     *   - Collection: [verdict=monitor, source=base, type=...]
     *
     * Note: Non expiring modules should always be placed before expiring modules.
     */

    std::array<rule_module_builder, rule_module_count> builders_{{
        // Network-ACL
        {base_rule_precedence, null_grouping_key, rule_module::expiration_policy::non_expiring},
        // Authentication-ACL
        {base_rule_precedence, null_grouping_key, rule_module::expiration_policy::non_expiring},
        // Custom-ACL
        {user_rule_precedence, null_grouping_key, rule_module::expiration_policy::expiring},
        // Configuration
        {user_rule_precedence, null_grouping_key, rule_module::expiration_policy::expiring},
        // Business logic
        {user_rule_precedence, null_grouping_key, rule_module::expiration_policy::expiring},
        // RASP
        {base_rule_precedence, null_grouping_key, rule_module::expiration_policy::expiring},
        // WAF
        {user_rule_precedence, type_grouping_key, rule_module::expiration_policy::expiring},
    }};
};

} // namespace ddwaf
