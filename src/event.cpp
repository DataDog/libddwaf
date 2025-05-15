// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "action_mapper.hpp"
#include "condition/base.hpp"
#include "ddwaf.h"
#include "event.hpp"
#include "rule.hpp"
#include "uuid.hpp"

namespace ddwaf {

namespace {

ddwaf_object *to_object(ddwaf_object &tmp, std::string_view str)
{
    if (str.empty()) {
        return ddwaf_object_stringl(&tmp, "", 0);
    }

    return ddwaf_object_stringl(&tmp, str.data(), str.size());
}

void serialize_match(condition_match &match, ddwaf_object &match_map, auto &obfuscator)
{
    ddwaf_object tmp;
    ddwaf_object param;
    ddwaf_object_map(&param);

    obfuscator.obfuscate_match(match);

    ddwaf_object highlight_arr;
    ddwaf_object_array(&highlight_arr);
    for (auto &highlight : match.highlights) {
        auto value = highlight.to_object();
        ddwaf_object_array_add(&highlight_arr, &value);
    }

    // Scalar case
    if (match.args.size() == 1 && match.args[0].name == "input") {
        auto &arg = match.args[0];

        ddwaf_object key_path;
        ddwaf_object_array(&key_path);
        for (const auto &key : arg.key_path) {
            ddwaf_object_array_add(&key_path, to_object(tmp, key));
        }

        ddwaf_object_map_add(&param, "address", to_object(tmp, arg.address));
        ddwaf_object_map_add(&param, "key_path", &key_path);
        auto resolved = arg.resolved.to_object();
        ddwaf_object_map_add(&param, "value", &resolved);
    } else {
        for (auto &arg : match.args) {
            ddwaf_object argument;
            ddwaf_object_map(&argument);

            ddwaf_object key_path;
            ddwaf_object_array(&key_path);
            for (auto &key : arg.key_path) {
                ddwaf_object_array_add(&key_path, to_object(tmp, key));
            }

            ddwaf_object_map_add(&argument, "address", to_object(tmp, arg.address));
            ddwaf_object_map_add(&argument, "key_path", &key_path);

            auto resolved = arg.resolved.to_object();
            ddwaf_object_map_add(&argument, "value", &resolved);

            ddwaf_object_map_addl(&param, arg.name.data(), arg.name.size(), &argument);
        }
    }

    ddwaf_object_map_add(&param, "highlight", &highlight_arr);

    ddwaf_object parameters;
    ddwaf_object_array(&parameters);
    ddwaf_object_array_add(&parameters, &param);

    ddwaf_object_map_add(&match_map, "operator", to_object(tmp, match.operator_name));
    ddwaf_object_map_add(&match_map, "operator_value", to_object(tmp, match.operator_value));
    ddwaf_object_map_add(&match_map, "parameters", &parameters);
}

// This structure is used to collect and deduplicate all actions, keep track of the
// blocking action with the highest precedence and of the relevant stack trace ID
struct action_tracker {
    // The blocking action refers to either a block_request or redirect_request
    // action, the latter having precedence over the former.
    std::string_view blocking_action;
    action_type blocking_action_type{action_type::none};

    // Stack trace ID
    std::string stack_id;

    // This set contains all remaining actions other than the blocking action
    std::unordered_set<std::string_view> non_blocking_actions;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const action_mapper &mapper;
};

void add_action_to_tracker(action_tracker &actions, std::string_view id, action_type type)
{
    if (is_blocking_action(type)) {
        if (type > actions.blocking_action_type) {
            // Only keep a single blocking action
            actions.blocking_action_type = type;
            actions.blocking_action = id;
        }
    } else {
        if (type == action_type::generate_stack && actions.stack_id.empty()) {
            // Stack trace actions require a dynamic stack ID, however we
            // only provide a single stack ID per run
            actions.stack_id = uuidv4_generate_pseudo();
        }

        actions.non_blocking_actions.emplace(id);
    }
}

void serialize_rule(const core_rule &rule, ddwaf_object &rule_map)
{
    ddwaf_object tmp;
    ddwaf_object tags_map;

    ddwaf_object_map(&rule_map);
    ddwaf_object_map(&tags_map);

    ddwaf_object_map_add(&rule_map, "id", to_object(tmp, rule.get_id()));
    ddwaf_object_map_add(&rule_map, "name", to_object(tmp, rule.get_name()));

    for (const auto &[key, value] : rule.get_tags()) {
        ddwaf_object_map_addl(&tags_map, key.c_str(), key.size(), to_object(tmp, value));
    }
    ddwaf_object_map_add(&rule_map, "tags", &tags_map);
}

void serialize_empty_rule(ddwaf_object &rule_map)
{
    ddwaf_object tmp;
    ddwaf_object tags_map;

    ddwaf_object_map(&tags_map);
    ddwaf_object_map_add(&tags_map, "type", to_object(tmp, ""));
    ddwaf_object_map_add(&tags_map, "category", to_object(tmp, ""));

    ddwaf_object_map(&rule_map);
    ddwaf_object_map_add(&rule_map, "id", to_object(tmp, ""));
    ddwaf_object_map_add(&rule_map, "name", to_object(tmp, ""));
    ddwaf_object_map_add(&rule_map, "tags", &tags_map);
}

void serialize_and_consolidate_rule_actions(const core_rule &rule, ddwaf_object &rule_map,
    std::string_view action_override, action_tracker &actions, ddwaf_object &stack_id)
{
    const auto &rule_actions = rule.get_actions();
    if (rule_actions.empty() && action_override.empty()) {
        return;
    }

    ddwaf_object tmp;
    ddwaf_object actions_array;
    ddwaf_object_array(&actions_array);

    if (!action_override.empty()) {
        auto action_it = actions.mapper.find(action_override);
        if (action_it != actions.mapper.end()) {
            const auto &[type, type_str, parameters] = action_it->second;

            // The action override must be either a blocking one or monitor
            if (type == action_type::monitor || is_blocking_action(type)) {
                add_action_to_tracker(actions, action_override, type);
            } else {
                // Clear the action override because it's not usable
                action_override = {};
            }
        } else {
            // Without a definition, the override can't be applied
            action_override = {};
        }

        // Tha override might have been clear if no definition was found
        if (!action_override.empty()) {
            ddwaf_object_array_add(&actions_array, to_object(tmp, action_override));
        }
    }

    for (const auto &action_id : rule_actions) {
        auto action_it = actions.mapper.find(action_id);
        if (action_it != actions.mapper.end()) {
            const auto &[type, type_str, parameters] = action_it->second;
            if (!action_override.empty() &&
                (type == action_type::monitor || is_blocking_action(type))) {
                // If the rule was in monitor mode, ignore blocking and monitor actions
                continue;
            }

            add_action_to_tracker(actions, action_id, type);

            // The stack ID will be generated when adding the action to the tracker
            if (type == action_type::generate_stack && stack_id.type == DDWAF_OBJ_INVALID) {
                to_object(stack_id, actions.stack_id);
            }
        }
        // If an action is unspecified, add it and move on
        ddwaf_object_array_add(&actions_array, to_object(tmp, action_id));
    }

    ddwaf_object_map_add(&rule_map, "on_match", &actions_array);
}

void serialize_action(std::string_view id, ddwaf_object &action_map, const action_tracker &actions)
{
    auto action_it = actions.mapper.find(id);
    if (action_it == actions.mapper.end()) {
        // If the action has no spec, we don't report it
        return;
    }

    const auto &[type, type_str, parameters] = action_it->second;
    if (type == action_type::monitor) {
        return;
    }

    ddwaf_object tmp;
    ddwaf_object param_map;
    ddwaf_object_map(&param_map);
    if (type != action_type::generate_stack) {
        for (const auto &[k, v] : parameters) {
            ddwaf_object_map_addl(
                &param_map, k.c_str(), k.size(), ddwaf_object_stringl(&tmp, v.c_str(), v.size()));
        }
    } else {
        ddwaf_object_map_addl(
            &param_map, "stack_id", sizeof("stack_id") - 1, to_object(tmp, actions.stack_id));
    }

    ddwaf_object_map_addl(&action_map, type_str.data(), type_str.size(), &param_map);
}

void serialize_actions(ddwaf_object &action_map, const action_tracker &actions)
{
    if (actions.blocking_action_type != action_type::none) {
        serialize_action(actions.blocking_action, action_map, actions);
    }

    for (const auto &id : actions.non_blocking_actions) {
        serialize_action(id, action_map, actions);
    }
}

} // namespace

void event_serializer::serialize(std::vector<event> &events,
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    ddwaf_object &output_events, ddwaf_object &output_actions) const
{
    action_tracker actions{
        .blocking_action = {}, .stack_id = {}, .non_blocking_actions = {}, .mapper = actions_};

    for (auto &event : events) {
        ddwaf_object root_map;
        ddwaf_object rule_map;
        ddwaf_object match_array;

        ddwaf_object_map(&root_map);
        ddwaf_object_array(&match_array);

        ddwaf_object stack_id;
        ddwaf_object_invalid(&stack_id);
        if (event.rule != nullptr) {
            serialize_rule(*event.rule, rule_map);
            serialize_and_consolidate_rule_actions(
                *event.rule, rule_map, event.action_override, actions, stack_id);
        } else {
            // This will only be used for testing
            serialize_empty_rule(rule_map);
        }

        for (auto &match : event.matches) {
            ddwaf_object match_map;
            ddwaf_object_map(&match_map);
            serialize_match(match, match_map, obfuscator_);
            ddwaf_object_array_add(&match_array, &match_map);
        }

        ddwaf_object_map_add(&root_map, "rule", &rule_map);
        ddwaf_object_map_add(&root_map, "rule_matches", &match_array);
        if (stack_id.type == DDWAF_OBJ_STRING) {
            ddwaf_object_map_add(&root_map, "stack_id", &stack_id);
        }

        ddwaf_object_array_add(&output_events, &root_map);
    }

    serialize_actions(output_actions, actions);
}

} // namespace ddwaf
