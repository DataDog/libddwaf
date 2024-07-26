// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "action_mapper.hpp"
#include "collection.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "obfuscator.hpp"
#include "processor/base.hpp"
#include "rule.hpp"
#include "scanner.hpp"

namespace ddwaf {

struct ruleset {
    void insert_rule(const std::shared_ptr<rule> &rule)
    {
        rules.emplace_back(rule);
        std::string_view type = rule->get_tag("type");
        std::string_view mod = rule->get_tag_or("module", "waf");

        auto [it, res] = collection_types.emplace(ddwaf::fmt::format("{}.{}", mod, type));
        const auto &collection = *it;
        if (rule->get_actions().empty()) {
            if (rule->get_source() == rule::source_type::user) {
                user_collections[collection].insert(rule);
            } else {
                base_collections[collection].insert(rule);
            }
        } else {
            if (rule->get_source() == rule::source_type::user) {
                user_priority_collections[collection].insert(rule);
            } else {
                base_priority_collections[collection].insert(rule);
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

    void insert_preprocessors(const auto &processors)
    {
        preprocessors = processors;
        for (const auto &[key, proc] : preprocessors) {
            proc->get_addresses(preprocessor_addresses);
        }
    }

    void insert_postprocessors(const auto &processors)
    {
        postprocessors = processors;
        for (const auto &[key, proc] : postprocessors) {
            proc->get_addresses(postprocessor_addresses);
        }
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
            for (const auto &[index, str] : preprocessor_addresses) {
                const auto &[it, res] = known_targets.emplace(index);
                if (res) {
                    root_addresses.emplace_back(str.c_str());
                }
            }
            for (const auto &[index, str] : postprocessor_addresses) {
                const auto &[it, res] = known_targets.emplace(index);
                if (res) {
                    root_addresses.emplace_back(str.c_str());
                }
            }
        }
        return root_addresses;
    }

    [[nodiscard]] const std::vector<const char *> &get_available_action_types()
    {
        if (available_action_types.empty()) {
            std::unordered_set<std::string_view> all_types;
            // We preallocate at least the total available actions in the mapper
            all_types.reserve(actions->size());

            auto maybe_add_action = [&](auto &&action) {
                auto it = actions->find(action);
                if (it == actions->end()) {
                    return;
                }
                auto [new_it, res] = all_types.emplace(it->second.type_str);
                if (res) {
                    available_action_types.emplace_back(it->second.type_str.c_str());
                }
            };

            for (const auto &rule : rules) {
                for (const auto &action : rule->get_actions()) { maybe_add_action(action); }
            }

            for (const auto &[name, filter] : rule_filters) {
                maybe_add_action(filter->get_action());
            }
        }
        return available_action_types;
    }

    ddwaf_object_free_fn free_fn{ddwaf_object_free};
    std::shared_ptr<ddwaf::obfuscator> event_obfuscator;

    std::unordered_map<std::string_view, std::shared_ptr<base_processor>> preprocessors;
    std::unordered_map<std::string_view, std::shared_ptr<base_processor>> postprocessors;

    std::unordered_map<std::string_view, std::shared_ptr<exclusion::rule_filter>> rule_filters;
    std::unordered_map<std::string_view, std::shared_ptr<exclusion::input_filter>> input_filters;

    std::vector<std::shared_ptr<rule>> rules;
    std::unordered_map<std::string, std::shared_ptr<matcher::base>> rule_matchers;
    std::unordered_map<std::string, std::shared_ptr<matcher::base>> exclusion_matchers;

    std::vector<std::shared_ptr<const scanner>> scanners;
    std::shared_ptr<action_mapper> actions;

    // The key used to organise collections is rule.type
    std::unordered_set<std::string> collection_types;
    std::unordered_map<std::string_view, priority_collection> user_priority_collections;
    std::unordered_map<std::string_view, priority_collection> base_priority_collections;
    std::unordered_map<std::string_view, collection> user_collections;
    std::unordered_map<std::string_view, collection> base_collections;

    std::unordered_map<target_index, std::string> rule_addresses;
    std::unordered_map<target_index, std::string> filter_addresses;
    std::unordered_map<target_index, std::string> preprocessor_addresses;
    std::unordered_map<target_index, std::string> postprocessor_addresses;

    // The following two members are computed only when required; they are
    // provided to the caller of ddwaf_known_* and are only cached for the
    // purpose of avoiding the need for a destruction method in the API.
    //
    // Root addresses, lazily computed
    std::vector<const char *> root_addresses;
    // A list of the possible action types that can be returned as a result of
    // the evaluation of the current set of rules and exclusion filters.
    // These are lazily computed andthe underlying memory of each string is
    // owned by the action mapper.
    std::vector<const char *> available_action_types;
};

} // namespace ddwaf
