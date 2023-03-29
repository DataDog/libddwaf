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

using rule_tag_map = ddwaf::multi_key_map<std::string_view, rule *>;

struct ruleset {
    using ptr = std::shared_ptr<ruleset>;

    void insert_rule(rule::ptr rule)
    {
        rules.emplace_back(rule);
        std::string_view type = rule->get_tag("type");
        collection_types.emplace(type);
        if (rule->actions.empty()) {
            if (rule->source == rule::source_type::user) {
                user_collections[type].insert(rule);
            } else {
                base_collections[type].insert(rule);
            }
        } else {
            if (rule->source == rule::source_type::user) {
                user_priority_collections[type].insert(rule);
            } else {
                base_priority_collections[type].insert(rule);
            }
        }
    }

    void insert_rules(const std::unordered_map<std::string_view, rule::ptr> &rules_)
    {
        for (const auto &[id, rule] : rules_) { insert_rule(rule); }
    }

    ddwaf_object_free_fn free_fn{ddwaf_object_free};
    std::shared_ptr<ddwaf::obfuscator> event_obfuscator;

    ddwaf::manifest manifest;
    std::unordered_map<std::string_view, exclusion::rule_filter::ptr> rule_filters;
    std::unordered_map<std::string_view, exclusion::input_filter::ptr> input_filters;

    // Rules are ordered by rule.id
    std::vector<rule::ptr> rules;
    std::unordered_map<std::string, rule_processor::base::ptr> dynamic_processors;

    // Both collections are ordered by rule.type
    std::unordered_set<std::string_view> collection_types;
    std::unordered_map<std::string_view, priority_collection> user_priority_collections;
    std::unordered_map<std::string_view, priority_collection> base_priority_collections;
    std::unordered_map<std::string_view, collection> user_collections;
    std::unordered_map<std::string_view, collection> base_collections;
};

} // namespace ddwaf
