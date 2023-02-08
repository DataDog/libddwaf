// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

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
#include <rule_data_dispatcher.hpp>

namespace ddwaf {

using sv_pair = std::pair<std::string_view, std::string_view>;

struct sv_pair_hash {
    std::size_t operator()(const sv_pair &t) const noexcept
    {
        return std::hash<std::string_view>()(t.first) ^ std::hash<std::string_view>()(t.second);
    }
};

using rule_tag_map = ddwaf::multi_key_map<sv_pair, rule::ptr, sv_pair_hash>;

struct ruleset {
    void insert_rule(rule::ptr rule)
    {
        rules.emplace(rule->id, rule);
        if (rule->actions.empty()) {
            collections[rule->get_tag("type")].insert(rule);
        } else {
            priority_collections[rule->get_tag("type")].insert(rule);
        }
        rules_by_type[rule->get_tag("type")].emplace(rule);
        rules_by_category[rule->get_tag("category")].emplace(rule);
    }

    std::set<rule::ptr> get_rules_by_type(std::string_view type) const
    {
        auto it = rules_by_type.find(type);
        if (it == rules_by_type.end()) {
            return {};
        }
        return it->second;
    }

    std::set<rule::ptr> get_rules_by_category(std::string_view category) const
    {
        auto it = rules_by_category.find(category);
        if (it == rules_by_category.end()) {
            return {};
        }
        return it->second;
    }

    std::set<rule::ptr> get_rules_by_type_and_category(
        std::string_view type, std::string_view category) const
    {
        auto type_it = rules_by_type.find(type);
        if (type_it == rules_by_type.end()) {
            return {};
        }

        auto category_it = rules_by_category.find(category);
        if (category_it == rules_by_category.end()) {
            return {};
        }

        const std::set<rule::ptr> &type_set = type_it->second;
        const std::set<rule::ptr> &category_set = category_it->second;
        std::set<rule::ptr> intersection;

        std::set_intersection(type_set.begin(), type_set.end(), category_set.begin(),
            category_set.end(), std::inserter(intersection, intersection.begin()));

        return intersection;
    }

    ddwaf_object_free_fn free_fn{ddwaf_object_free};
    ddwaf::obfuscator event_obfuscator;

    ddwaf::manifest manifest;
    std::unordered_map<std::string_view, exclusion::rule_filter::ptr> rule_filters;
    std::unordered_map<std::string_view, exclusion::input_filter::ptr> input_filters;

    // Rules are ordered by rule.id
    std::unordered_map<std::string, rule::ptr> rules;

    // Both collections are ordered by rule.type
    std::unordered_map<std::string_view, priority_collection> priority_collections;
    std::unordered_map<std::string_view, collection> collections;

    ddwaf::rule_data::dispatcher dispatcher;

    std::unordered_map<std::string_view, std::set<rule::ptr>> rules_by_type;
    std::unordered_map<std::string_view, std::set<rule::ptr>> rules_by_category;
};

} // namespace ddwaf
