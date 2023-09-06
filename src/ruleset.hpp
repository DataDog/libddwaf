// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <algorithm>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include <collection.hpp>
#include <exclusion/input_filter.hpp>
#include <exclusion/rule_filter.hpp>
#include <mkmap.hpp>
#include <obfuscator.hpp>
#include <processor.hpp>
#include <rule.hpp>
#include <scanner.hpp>

namespace ddwaf {

struct ruleset {

    void insert_rule(const std::shared_ptr<rule> &rule)
    {
        rules.emplace_back(rule);
        std::string_view type = rule->get_tag("type");
        collection_types.emplace(type);
        if (rule->get_actions().empty()) {
            if (rule->get_source() == rule::source_type::user) {
                user_collections[type].insert(rule);
            } else {
                base_collections[type].insert(rule);
            }
        } else {
            if (rule->get_source() == rule::source_type::user) {
                user_priority_collections[type].insert(rule);
            } else {
                base_priority_collections[type].insert(rule);
            }
        }
        rule->get_addresses(rule_addresses);
    }

    void insert_rules(const std::vector<std::shared_ptr<rule>> &rules_)
    {
        for (const auto &rule : rules_) { insert_rule(rule); }
    }

    template <typename T>
    void insert_filters(const std::unordered_map<std::string_view, std::shared_ptr<T>> &filters)
        requires std::is_same_v<T, exclusion::rule_filter> or
                 std::is_same_v<T, exclusion::input_filter>
    {
        if constexpr (std::is_same_v<T, exclusion::rule_filter>) {
            rule_filters = filters;
        } else if constexpr (std::is_same_v<T, exclusion::input_filter>) {
            input_filters = filters;
        }

        for (const auto &[key, filter] : filters) { filter->get_addresses(filter_addresses); }
    }

    template <typename T>
    void insert_filter(const std::shared_ptr<T> &filter)
        requires std::is_same_v<T, exclusion::rule_filter> or
                 std::is_same_v<T, exclusion::input_filter>
    {
        if constexpr (std::is_same_v<T, exclusion::rule_filter>) {
            rule_filters.emplace(filter->get_id(), filter);
        } else if constexpr (std::is_same_v<T, exclusion::input_filter>) {
            input_filters.emplace(filter->get_id(), filter);
        }
        filter->get_addresses(filter_addresses);
    }

    [[nodiscard]] const std::vector<const char *> &get_root_addresses()
    {
        if (root_addresses.empty()) {
            std::unordered_set<target_index> known_targets;
            for (const auto &[index, str] : rule_addresses) {
                const auto &[it, res] = known_targets.emplace(index);
                if (res) {
                    root_addresses.emplace_back(str.c_str());
                }
            }
            for (const auto &[index, str] : filter_addresses) {
                const auto &[it, res] = known_targets.emplace(index);
                if (res) {
                    root_addresses.emplace_back(str.c_str());
                }
            }
        }
        return root_addresses;
    }

    ddwaf_object_free_fn free_fn{ddwaf_object_free};
    std::shared_ptr<ddwaf::obfuscator> event_obfuscator;

    std::unordered_map<std::string_view, std::shared_ptr<processor>> preprocessors;
    std::unordered_map<std::string_view, std::shared_ptr<processor>> postprocessors;

    std::unordered_map<std::string_view, std::shared_ptr<exclusion::rule_filter>> rule_filters;
    std::unordered_map<std::string_view, std::shared_ptr<exclusion::input_filter>> input_filters;

    std::vector<std::shared_ptr<rule>> rules;
    std::unordered_map<std::string, std::shared_ptr<matcher::base>> dynamic_matchers;

    std::vector<std::shared_ptr<const scanner>> scanners;

    // The key used to organise collections is rule.type
    std::unordered_set<std::string_view> collection_types;
    std::unordered_map<std::string_view, priority_collection> user_priority_collections;
    std::unordered_map<std::string_view, priority_collection> base_priority_collections;
    std::unordered_map<std::string_view, collection> user_collections;
    std::unordered_map<std::string_view, collection> base_collections;

    std::unordered_map<target_index, std::string> rule_addresses;
    std::unordered_map<target_index, std::string> filter_addresses;

    // Root addresses, lazily computed
    std::vector<const char *> root_addresses;
};

} // namespace ddwaf
