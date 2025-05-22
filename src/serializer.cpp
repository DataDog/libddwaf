// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "action_mapper.hpp"
#include "attribute_collector.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "ddwaf.h"
#include "obfuscator.hpp"
#include "object_store.hpp"
#include "rule.hpp"
#include "serializer.hpp"
#include "utils.hpp"
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

void serialize_match(condition_match &match, ddwaf_object &match_map)
{
    ddwaf_object tmp;
    ddwaf_object param;
    ddwaf_object_map(&param);

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

std::pair<ddwaf_object, /*stack id*/ bool> serialize_and_consolidate_actions(
    std::string_view action_override, const std::vector<std::string> &rule_actions,
    action_tracker &actions)
{
    ddwaf_object tmp;
    ddwaf_object actions_array;
    ddwaf_object_array(&actions_array);

    if (rule_actions.empty() && action_override.empty()) {
        return {actions_array, false};
    }

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

    bool has_stack_id = false;
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
            if (type == action_type::generate_stack) {
                has_stack_id = true;
            }
        }
        // If an action is unspecified, add it and move on
        ddwaf_object_array_add(&actions_array, to_object(tmp, action_id));
    }

    return {actions_array, has_stack_id};
}

void consolidate_actions(std::string_view action_override,
    const std::vector<std::string> &rule_actions, action_tracker &actions)
{
    if (rule_actions.empty() && action_override.empty()) {
        return;
    }

    if (!action_override.empty()) {
        auto action_it = actions.mapper.find(action_override);
        if (action_it != actions.mapper.end()) {
            const auto &[type, type_str, parameters] = action_it->second;

            // The action override must be either a blocking one or monitor
            if (type == action_type::monitor || is_blocking_action(type)) {
                add_action_to_tracker(actions, action_override, type);
            }
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
        }
    }
}

void serialize_event(rule_event &event, const match_obfuscator &obfuscator,
    std::string_view action_override, const std::vector<std::string> &rule_actions,
    action_tracker &actions, ddwaf_object &event_array)
{
    ddwaf_object tmp;

    ddwaf_object tags_map;
    ddwaf_object_map(&tags_map);
    for (const auto &[key, value] : event.rule.tags.get()) {
        ddwaf_object_map_addl(&tags_map, key.c_str(), key.size(), to_object(tmp, value));
    }

    ddwaf_object rule_map;
    ddwaf_object_map(&rule_map);
    ddwaf_object_map_add(&rule_map, "id", to_object(tmp, event.rule.id));
    ddwaf_object_map_add(&rule_map, "name", to_object(tmp, event.rule.name));
    ddwaf_object_map_add(&rule_map, "tags", &tags_map);

    auto [actions_array, has_stack_id] =
        serialize_and_consolidate_actions(action_override, rule_actions, actions);
    ddwaf_object_map_add(&rule_map, "on_match", &actions_array);

    ddwaf_object match_array;
    ddwaf_object_array(&match_array);
    for (auto &match : event.matches) {
        obfuscator.obfuscate_match(match);

        ddwaf_object match_map;
        ddwaf_object_map(&match_map);
        serialize_match(match, match_map);
        ddwaf_object_array_add(&match_array, &match_map);
    }

    ddwaf_object root_map;
    ddwaf_object_map(&root_map);
    ddwaf_object_map_add(&root_map, "rule", &rule_map);
    ddwaf_object_map_add(&root_map, "rule_matches", &match_array);
    if (has_stack_id) {
        ddwaf_object_map_add(&root_map, "stack_id", to_object(tmp, actions.stack_id));
    }

    ddwaf_object_array_add(&event_array, &root_map);
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

void collect_attributes(const object_store &store, const std::vector<rule_attribute> &attributes,
    attribute_collector &collector)
{
    for (const auto &attr : attributes) {
        if (std::holds_alternative<rule_attribute::input_target>(attr.input)) {
            auto input = std::get<rule_attribute::input_target>(attr.input);
            collector.collect(store, input.index, input.key_path, attr.output);
        } else if (std::holds_alternative<std::string>(attr.input)) {
            collector.insert(attr.output, std::get<std::string>(attr.input));
        } else if (std::holds_alternative<uint64_t>(attr.input)) {
            collector.insert(attr.output, std::get<uint64_t>(attr.input));
        } else if (std::holds_alternative<int64_t>(attr.input)) {
            collector.insert(attr.output, std::get<int64_t>(attr.input));
        } else if (std::holds_alternative<double>(attr.input)) {
            collector.insert(attr.output, std::get<double>(attr.input));
        } else if (std::holds_alternative<bool>(attr.input)) {
            collector.insert(attr.output, std::get<bool>(attr.input));
        }
    }
}

} // namespace

void result_serializer::serialize(const object_store &store, std::vector<rule_result> &results,
    attribute_collector &collector, const timer &deadline, result_components output) const
{
    action_tracker actions{
        .blocking_action = {}, .stack_id = {}, .non_blocking_actions = {}, .mapper = actions_};

    // First collect any pending attributes from previous runs
    collector.collect_pending(store);

    bool final_keep = false;
    for (auto &result : results) {
        final_keep |= result.keep;

        if (result.event) {
            serialize_event(result.event.value(), obfuscator_, result.action_override,
                result.actions, actions, output.events);
        } else {
            consolidate_actions(result.action_override, result.actions, actions);
        }

        collect_attributes(store, result.attributes.get(), collector);
    }

    // Using the interface functions would replace the key contained within the
    // object. This will not be an issue in v2.
    output.duration.uintValue = deadline.elapsed().count();
    output.timeout.boolean = deadline.expired_before();
    output.keep.boolean = final_keep;

    object::assign(output.attributes, collector.get_available_attributes_and_reset());
    serialize_actions(output.actions, actions);
}

std::pair<ddwaf_object, result_components> result_serializer::initialise_result_object()
{
    ddwaf_object object;
    ddwaf_object_map(&object);

    bool add_res = true;
    ddwaf_object tmp;
    add_res &= ddwaf_object_map_addl(&object, STRL("events"), ddwaf_object_array(&tmp));
    add_res &= ddwaf_object_map_addl(&object, STRL("actions"), ddwaf_object_map(&tmp));
    add_res &= ddwaf_object_map_addl(&object, STRL("duration"), ddwaf_object_unsigned(&tmp, 0));
    add_res &= ddwaf_object_map_addl(&object, STRL("timeout"), ddwaf_object_bool(&tmp, false));
    add_res &= ddwaf_object_map_addl(&object, STRL("attributes"), ddwaf_object_map(&tmp));
    add_res &= ddwaf_object_map_addl(&object, STRL("keep"), ddwaf_object_bool(&tmp, false));

    if (!add_res) {
        throw std::runtime_error("failed to generate result object");
    }

    const result_components res{.events = object.array[0],
        .actions = object.array[1],
        .duration = object.array[2],
        .timeout = object.array[3],
        .attributes = object.array[4],
        .keep = object.array[5]};

    return {object, res};
}

} // namespace ddwaf
