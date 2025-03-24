// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "action_mapper.hpp"
#include "condition/base.hpp"
#include "ddwaf.h"
#include "event.hpp"
#include "obfuscator.hpp"
#include "object.hpp"
#include "rule.hpp"
#include "uuid.hpp"

namespace ddwaf {

namespace {

bool redact_match(const ddwaf::obfuscator &obfuscator, const condition_match &match)
{
    for (const auto &arg : match.args) {
        for (const auto &key : arg.key_path) {
            if (obfuscator.is_sensitive_key(key)) {
                return true;
            }
        }

        if (obfuscator.is_sensitive_value(arg.resolved)) {
            return true;
        }
    }

    for (const auto &highlight : match.highlights) {
        if (obfuscator.is_sensitive_value(highlight)) {
            return true;
        }
    }

    return false;
}

owned_object serialize_match(const condition_match &match, auto &obfuscator)
{
    auto match_map = owned_object::make_map();

    const bool redact = redact_match(obfuscator, match);

    match_map.emplace("operator", match.operator_name);
    match_map.emplace("operator_value", match.operator_value);

    auto parameters = match_map.emplace("parameters", owned_object::make_array());
    auto param = parameters.emplace_back(owned_object::make_map());

    auto highlight_arr = param.emplace("highlight", owned_object::make_array());
    for (const auto &highlight : match.highlights) {
        if (redact) {
            highlight_arr.emplace_back(ddwaf::obfuscator::redaction_msg);
        } else {
            highlight_arr.emplace_back(highlight);
        }
    }

    // Scalar case
    if (match.args.size() == 1 && match.args[0].name == "input") {
        const auto &arg = match.args[0];

        param.emplace("address", arg.address);

        if (redact) {
            param.emplace("value", ddwaf::obfuscator::redaction_msg);
        } else {
            param.emplace("value", arg.resolved);
        }

        auto key_path = param.emplace("key_path", owned_object::make_array());
        for (const auto &key : arg.key_path) { key_path.emplace_back(key); }
    } else {
        for (const auto &arg : match.args) {
            auto argument = param.emplace(arg.name, owned_object::make_map());

            argument.emplace("address", arg.address);

            if (redact) {
                argument.emplace("value", ddwaf::obfuscator::redaction_msg);
            } else {
                argument.emplace("value", arg.resolved);
            }

            auto key_path = argument.emplace("key_path", owned_object::make_array());
            for (const auto &key : arg.key_path) { key_path.emplace_back(key); }
        }
    }

    return match_map;
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

owned_object serialize_rule(const core_rule &rule)
{
    auto rule_map = owned_object::make_map();
    rule_map.emplace("id", rule.get_id());
    rule_map.emplace("name", rule.get_name());

    auto tags_map = rule_map.emplace("tags", owned_object::make_map());
    for (const auto &[key, value] : rule.get_tags()) { tags_map.emplace(key, value); }
    return rule_map;
}

owned_object serialize_empty_rule()
{
    auto rule_map = owned_object::make_map();
    rule_map.emplace("id", "");
    rule_map.emplace("name", "");

    auto tags_map = rule_map.emplace("tags", owned_object::make_map());
    tags_map.emplace("type", "");
    tags_map.emplace("category", "");

    return rule_map;
}

void serialize_and_consolidate_rule_actions(const core_rule &rule, owned_object &rule_map,
    std::string_view action_override, action_tracker &actions, owned_object &stack_id)
{
    const auto &rule_actions = rule.get_actions();
    if (rule_actions.empty() && action_override.empty()) {
        return;
    }

    auto actions_array = rule_map.emplace("on_match", owned_object::make_array());

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
            actions_array.emplace_back(action_override);
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
            if (type == action_type::generate_stack && stack_id.is_invalid()) {
                stack_id = owned_object{actions.stack_id};
            }
        }
        // If an action is unspecified, add it and move on
        actions_array.emplace_back(action_id);
    }
}

void serialize_action(std::string_view id, owned_object &action_map, const action_tracker &actions)
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

    auto param_map = action_map.emplace(type_str, owned_object::make_map());
    if (type != action_type::generate_stack) {
        for (const auto &[k, v] : parameters) { param_map.emplace(k, v); }
    } else {
        param_map.emplace("stack_id", actions.stack_id);
    }
}

owned_object serialize_actions(const action_tracker &actions)
{
    auto action_map = owned_object::make_map();

    if (actions.blocking_action_type != action_type::none) {
        serialize_action(actions.blocking_action, action_map, actions);
    }

    for (const auto &id : actions.non_blocking_actions) {
        serialize_action(id, action_map, actions);
    }

    return action_map;
}

} // namespace

void event_serializer::serialize(const std::vector<event> &events, ddwaf_result &output) const
{
    if (events.empty()) {
        return;
    }

    action_tracker actions{
        .blocking_action = {}, .stack_id = {}, .non_blocking_actions = {}, .mapper = actions_};

    auto events_array = owned_object::make_array();
    for (const auto &event : events) {
        auto root_map = events_array.emplace_back(owned_object::make_map());
        auto match_array = owned_object::make_array();

        owned_object rule_map;
        owned_object stack_id;
        if (event.rule != nullptr) {
            rule_map = serialize_rule(*event.rule);
            serialize_and_consolidate_rule_actions(
                *event.rule, rule_map, event.action_override, actions, stack_id);
        } else {
            // This will only be used for testing
            rule_map = serialize_empty_rule();
        }

        for (const auto &match : event.matches) {
            match_array.emplace_back(serialize_match(match, obfuscator_));
        }

        root_map.emplace("rule", std::move(rule_map));
        root_map.emplace("rule_matches", std::move(match_array));
        if (stack_id.is_valid()) {
            root_map.emplace("stack_id", std::move(stack_id));
        }
    }

    output.events = events_array.move();
    output.actions = serialize_actions(actions).move();
}

} // namespace ddwaf
