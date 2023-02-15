// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include <collection.hpp>
#include <exclusion/input_filter.hpp>
#include <exclusion/rule_filter.hpp>
#include <manifest.hpp>
#include <mkmap.hpp>
#include <obfuscator.hpp>
#include <rule.hpp>

namespace ddwaf {

using rule_tag_map = ddwaf::multi_key_map<std::string_view, rule::ptr>;

struct ruleset {
    using ptr = std::shared_ptr<ruleset>;

    void insert_rule(rule::ptr rule)
    {
        rules.emplace(rule->id, rule);
        if (rule->actions.empty()) {
            collections[rule->get_tag("type")].insert(rule);
        } else {
            priority_collections[rule->get_tag("type")].insert(rule);
        }
    }

    void insert_rules(std::unordered_map<std::string_view, rule::ptr> rules_)
    {
        rules = std::move(rules_);

        for (const auto &[id, rule] : rules) {
            if (rule->actions.empty()) {
                collections[rule->get_tag("type")].insert(rule);
            } else {
                priority_collections[rule->get_tag("type")].insert(rule);
            }
        }
    }

    ddwaf_object_free_fn free_fn{ddwaf_object_free};
    std::shared_ptr<ddwaf::obfuscator> event_obfuscator;

    ddwaf::manifest manifest;
    std::unordered_map<std::string_view, exclusion::rule_filter::ptr> rule_filters;
    std::unordered_map<std::string_view, exclusion::input_filter::ptr> input_filters;

    // Rules are ordered by rule.id
    std::unordered_map<std::string_view, rule::ptr> rules;
    std::unordered_map<std::string, rule_processor::base::ptr> dynamic_processors;

    // Both collections are ordered by rule.type
    std::unordered_map<std::string_view, priority_collection> priority_collections;
    std::unordered_map<std::string_view, collection> collections;
};

} // namespace ddwaf
