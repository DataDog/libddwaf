// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "parser/specification.hpp"
#include <manifest.hpp>
#include <memory>
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
    using ptr = std::shared_ptr<builder>;

    builder(object_limits limits, ddwaf_object_free_fn free_fn, ddwaf::obfuscator event_obfuscator)
        : limits_(limits), free_fn_(free_fn), event_obfuscator_(std::move(event_obfuscator))
    {}

    ~builder() = default;
    builder(builder &&) = default;
    builder(const builder &) = delete;
    builder &operator=(builder &&) = delete;
    builder &operator=(const builder &) = delete;

    std::shared_ptr<ruleset> build(parameter root, ruleset_info &info)
    {
        parameter::map input = root;
        return build(input, info);
    }

    std::shared_ptr<ruleset> build(parameter::map &root, ruleset_info &info);

protected:
    enum class change_state : uint32_t {
        none = 0,
        rules = 1,
        overrides = 2,
        filters = 4,
        data = 8
    };

    friend constexpr change_state operator|(change_state lhs, change_state rhs);
    friend constexpr change_state operator&(change_state lhs, change_state rhs);

    change_state load(parameter::map &root, ruleset_info &info);

    // These members are obtained through ddwaf_config and are persistent across
    // all updates.
    const object_limits limits_;
    const ddwaf_object_free_fn free_fn_;
    const ddwaf::obfuscator event_obfuscator_;

    // The same manifest is used across updates, so we need to ensure that
    // unused targets are regularly cleaned up.
    manifest target_manifest_;
    // Map representing rule data IDs to processor type, this is obtained
    // from parsing the ruleset ('rules' key).
    std::unordered_map<std::string, std::string> rule_data_ids_;

    // These contain the specification of each main component obtained directly
    // from the parser. These are only modified on update, if the relevant key
    // is present and valid, otherwise they aren't be updated.
    // Note that in the case of dynamic_processors, overrides and exclusions
    // we allow an empty key as a way to revert or remove the contents of the
    // relevant feature.

    // Obtained from 'rules', can't be empty
    parser::rule_spec_container base_rules_;
    // Obtained from 'rules_data', depends on base_rules_
    parser::rule_data_container dynamic_processors_;
    // Obtained from 'rules_override'
    parser::override_spec_container overrides_;
    // Obtained from 'exclusions'
    parser::filter_spec_container exclusions_;

    // These are the contents of the latest generated ruleset

    // Rules
    std::unordered_map<std::string_view, rule::ptr> final_rules_;
    // An mkmap organising rules by their tags, used for overrides and exclusion filters
    rule_tag_map rules_by_tags_;
    // The list of tagets used by the rules in final_rules_, used for manifest cleanup
    std::unordered_set<manifest::target_type> targets_from_rules_;

    // Filters
    std::unordered_map<std::string_view, exclusion::rule_filter::ptr> rule_filters_;
    std::unordered_map<std::string_view, exclusion::input_filter::ptr> input_filters_;
    // The list of targets used by rule_filters_, input_filters_ and their internal
    // object filters, used for manifest cleanup
    std::unordered_set<manifest::target_type> targets_from_filters_;
};

} // namespace ddwaf
