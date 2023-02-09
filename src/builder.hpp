// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "parser/specification.hpp"
#include <manifest.hpp>
#include <parameter.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace ddwaf {

class builder {
public:
    builder() = default;
    ~builder() = default;
    builder(builder &&) = default;
    builder(const builder &) = delete;
    builder &operator=(builder &&) = default;
    builder &operator=(const builder &) = delete;

    std::shared_ptr<ruleset> build(parameter object, ruleset_info &info, object_limits limits);

protected:
    enum class change_state : uint32_t { none = 0, rules = 1, overrides = 2, filters = 4 };

    friend change_state operator|(change_state lhs, change_state rhs);
    friend change_state operator&(change_state lhs, change_state rhs);

    std::shared_ptr<ruleset> build_helper(
        parameter::map root, ruleset_info &info, object_limits limits);

    builder::change_state load(parameter::map &root, ruleset_info &info, object_limits limits);

    // First stage
    parser::rule_spec_container base_rules_;
    parser::override_spec_container overrides_;
    parser::filter_spec_container exclusions_;

    // Second stage
    using rule_spec_tag_map = ddwaf::multi_key_map<sv_pair, std::string, sv_pair_hash>;
    rule_spec_tag_map rule_specs_by_tag_;

    // Third stage
    parser::rule_spec_container overridden_rules_;

    // Fourth stage
    std::unordered_map<std::string_view, rule::ptr> final_rules_;

    // Fifth stage
    rule_tag_map rules_by_tags_;
};

} // namespace ddwaf
