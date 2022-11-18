// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <set>
#include <unordered_map>
#include <vector>

#include <exclusion_filter.hpp>
#include <manifest.hpp>
#include <rule.hpp>
#include <rule_data_dispatcher.hpp>

namespace ddwaf {

struct ruleset {
    void insert_rule(rule_base::ptr rule)
    {
        rules.emplace(rule->id, rule);
        collections[rule->type].emplace_back(rule);
        rules_by_type[rule->type].emplace(rule);
        rules_by_category[rule->category].emplace(rule);
    }

    std::set<rule_base::ptr> get_rules_by_type(std::string_view type) const
    {
        auto it = rules_by_type.find(type);
        if (it == rules_by_type.end()) {
            return {};
        }
        return it->second;
    }

    std::set<rule_base::ptr> get_rules_by_category(std::string_view category) const
    {
        auto it = rules_by_category.find(category);
        if (it == rules_by_category.end()) {
            return {};
        }
        return it->second;
    }

    std::set<rule_base::ptr> get_rules_by_type_and_category(
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

        const std::set<rule_base::ptr> &type_set = type_it->second;
        const std::set<rule_base::ptr> &category_set = category_it->second;
        std::set<rule_base::ptr> intersection;

        std::set_intersection(type_set.begin(), type_set.end(), category_set.begin(),
            category_set.end(), std::inserter(intersection, intersection.begin()));

        return intersection;
    }

    ddwaf::manifest manifest;
    std::vector<exclusion_filter::ptr> filters;
    // Rules are ordered by ID
    std::unordered_map<std::string, rule_base::ptr> rules;
    // Collections are ordered by rule.type
    std::unordered_map<std::string, std::vector<rule_base::ptr>> collections;
    ddwaf::rule_data::dispatcher dispatcher;

    std::unordered_map<std::string_view, std::set<rule_base::ptr>> rules_by_type;
    std::unordered_map<std::string_view, std::set<rule_base::ptr>> rules_by_category;
};

} // namespace ddwaf
