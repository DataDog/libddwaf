// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "parser/specification.hpp"
#include <memory>
#include <parameter.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace ddwaf {

class ruleset_builder {
public:
    using ptr = std::shared_ptr<ruleset_builder>;

    ruleset_builder(object_limits limits, ddwaf_object_free_fn free_fn,
        std::shared_ptr<ddwaf::obfuscator> event_obfuscator)
        : limits_(limits), free_fn_(free_fn), event_obfuscator_(std::move(event_obfuscator))
    {}

    ~ruleset_builder() = default;
    ruleset_builder(ruleset_builder &&) = default;
    ruleset_builder(const ruleset_builder &) = delete;
    ruleset_builder &operator=(ruleset_builder &&) = delete;
    ruleset_builder &operator=(const ruleset_builder &) = delete;

    std::shared_ptr<ruleset> build(parameter root_map, base_ruleset_info &info)
    {
        auto root = static_cast<parameter::map>(root_map);
        return build(root, info);
    }

    std::shared_ptr<ruleset> build(parameter::map &root, base_ruleset_info &info);

protected:
    enum class change_state : uint32_t {
        none = 0,
        rules = 1,
        custom_rules = 2,
        overrides = 4,
        filters = 8,
        data = 16,
        processors = 32,
    };

    friend constexpr change_state operator|(change_state lhs, change_state rhs);
    friend constexpr change_state operator&(change_state lhs, change_state rhs);

    change_state load(parameter::map &root, base_ruleset_info &info);

    // These members are obtained through ddwaf_config and are persistent across
    // all updates.
    const object_limits limits_;
    const ddwaf_object_free_fn free_fn_;
    std::shared_ptr<ddwaf::obfuscator> event_obfuscator_;

    // Map representing rule data IDs to matcher type, this is obtained
    // from parsing the ruleset ('rules' key).
    std::unordered_map<std::string, std::string> rule_data_ids_;

    // These contain the specification of each main component obtained directly
    // from the parser. These are only modified on update, if the relevant key
    // is present and valid, otherwise they aren't be updated.
    // Note that in the case of dynamic_matchers, overrides and exclusions
    // we allow an empty key as a way to revert or remove the contents of the
    // relevant feature.

    // Obtained from 'rules', can't be empty
    parser::rule_spec_container base_rules_;
    // Obtained from 'custom_rules'
    parser::rule_spec_container user_rules_;
    // Obtained from 'rules_data', depends on base_rules_
    parser::rule_data_container dynamic_matchers_;
    // Obtained from 'rules_override'
    parser::override_spec_container overrides_;
    // Obtained from 'exclusions'
    parser::filter_spec_container exclusions_;
    // Obtained from 'processors'
    parser::processor_container preprocessors_;
    parser::processor_container postprocessors_;

    // These are the contents of the latest generated ruleset

    // Rules
    std::unordered_map<std::string_view, rule::ptr> final_base_rules_;
    std::unordered_map<std::string_view, rule::ptr> final_user_rules_;

    // An mkmap organising rules by their tags, used for overrides and exclusion filters
    rule_tag_map base_rules_by_tags_;
    rule_tag_map user_rules_by_tags_;

    // Filters
    std::unordered_map<std::string_view, exclusion::rule_filter::ptr> rule_filters_;
    std::unordered_map<std::string_view, exclusion::input_filter::ptr> input_filters_;
    // The list of targets used by rule_filters_, input_filters_ and their internal
};

} // namespace ddwaf
