// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <unordered_set>

#include "action_mapper.hpp"
#include "ddwaf.h"
#include "event.hpp"
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

owned_object redacted_object(std::string_view str, bool redact = false)
{
    if (str.empty()) {
        return owned_object::make_string("");
    }

    if (redact) {
        return owned_object::make_string(ddwaf::obfuscator::redaction_msg);
    }
    return owned_object::make_string(str);
}
owned_object serialize_match(const condition_match &match, auto &obfuscator)
{
    auto match_map = owned_object::make_map(3);
    match_map.emplace("operator", owned_object::make_string(match.operator_name));
    match_map.emplace("operator_value", owned_object::make_string(match.operator_value));

    bool redact = redact_match(obfuscator, match);
    borrowed_object param;

    // Scalar case
    if (match.args.size() == 1 && match.args[0].name == "input") {
        const auto &arg = match.args[0];

        param = match_map.emplace("parameters", owned_object::make_array(3 + 1));
        param.emplace("address", owned_object::make_string(arg.address));

        auto key_path = param.emplace("key_path", owned_object::make_array(arg.key_path.size()));
        for (const auto &key : arg.key_path) {
            key_path.emplace_back(owned_object::make_string(key));
        }
        param.emplace("value", redacted_object(arg.resolved, redact));
    } else {
        param = match_map.emplace("parameters", owned_object::make_array(match.args.size() + 1));
        for (const auto &arg : match.args) {
            auto argument = param.emplace(arg.name, owned_object::make_array(3));

            argument.emplace("address", owned_object::make_string(arg.address));

            auto key_path =
                argument.emplace("key_path", owned_object::make_array(arg.key_path.size()));
            for (const auto &key : arg.key_path) {
                key_path.emplace_back(owned_object::make_string(key));
            }
            argument.emplace("value", redacted_object(arg.resolved, redact));
        }
    }

    auto hlight_arr = param.emplace("highlight", owned_object::make_array(match.highlights.size()));
    for (const auto &highlight : match.highlights) {
        hlight_arr.emplace_back(redacted_object(highlight, redact));
    }

    return match_map;
}

// This structure is used to collect and deduplicate all actions, keep track of the
// blocking action with the highest precedence and of the relevant stack trace ID
struct action_tracker {
    // The blocking action refers to either a block_request or redirect_request
    // action, the latter having precedence over the former.
    std::string_view blocking_action{};
    action_type blocking_action_type{action_type::none};

    // Stack trace ID
    std::string stack_id{};

    // This set contains all remaining actions other than the blocking action
    std::unordered_set<std::string_view> non_blocking_actions{};

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

owned_object serialize_rule(const ddwaf::rule &rule, action_tracker &actions,
    action_type action_override, bool &set_stack_id)
{
    const auto &rule_actions = rule.get_actions();

    auto rule_map = owned_object::make_map(rule_actions.empty() ? 3 : 4);
    rule_map.emplace("id", owned_object::make_string(rule.get_id()));
    rule_map.emplace("name", owned_object::make_string(rule.get_name()));

    const auto &rule_tags = rule.get_tags();
    auto tags_map = rule_map.emplace("tags", owned_object::make_map(rule_tags.size()));

    for (const auto &[key, value] : rule.get_tags()) {
        tags_map.emplace(key, owned_object::make_string(value));
    }

    // Return here if there are no actions
    if (rule_actions.empty()) {
        return rule_map;
    }

    auto actions_array =
        rule_map.emplace("on_match", owned_object::make_array(rule_actions.size()));
    if (action_override == action_type::monitor) {
        actions_array.emplace_back(owned_object::make_string("monitor"));
    }

    for (const auto &action_id : rule_actions) {
        auto action_it = actions.mapper.find(action_id);
        if (action_it != actions.mapper.end()) {
            const auto &[type, type_str, parameters] = action_it->second;
            if (action_override == action_type::monitor &&
                (type == action_type::monitor || is_blocking_action(type))) {
                // If the rule was in monitor mode, ignore blocking and monitor actions
                continue;
            }

            set_stack_id = (type == action_type::generate_stack);

            add_action_to_tracker(actions, action_id, type);
        }
        // If an action is unspecified, add it and move on
        actions_array.emplace_back(owned_object::make_string(action_id));
    }

    return rule_map;
}

owned_object serialize_empty_rule()
{
    auto rule_map = owned_object::make_map(3);
    rule_map.emplace("id", owned_object::make_string(""));
    rule_map.emplace("name", owned_object::make_string(""));

    auto tags = rule_map.emplace("tags", owned_object::make_map(2));
    tags.emplace("type", owned_object::make_string(""));
    tags.emplace("category", owned_object::make_string(""));

    return rule_map;
}

void serialize_action(std::string_view id, auto &action_map, const action_tracker &actions)
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

    borrowed_object param_map;
    if (type != action_type::generate_stack) {
        param_map = action_map.emplace(type_str, owned_object::make_map(parameters.size()));
        for (const auto &[k, v] : parameters) {
            param_map.emplace(k, owned_object::make_string(v));
        }
    } else {
        param_map = action_map.emplace(type_str, owned_object::make_map(1));
        param_map.emplace("stack_id", owned_object::make_string(actions.stack_id));
    }
}

owned_object serialize_actions(const action_tracker &actions)
{
    auto action_map = owned_object::make_map(actions.non_blocking_actions.size() + 1);

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

    action_tracker actions{.mapper = actions_};

    auto events_array = owned_object::make_array(events.size());
    for (const auto &event : events) {
        auto root_map = events_array.emplace_back(owned_object::make_map(4));

        bool set_stack_id = false;
        if (event.rule != nullptr) {
            root_map.emplace(
                "rule", serialize_rule(*event.rule, actions, event.action_override, set_stack_id));
        } else {
            // This will only be used for testing
            root_map.emplace("rule", serialize_empty_rule());
        }

        auto match_array =
            root_map.emplace("rule_matches", owned_object::make_array(event.matches.size()));
        for (const auto &match : event.matches) {
            match_array.emplace_back(serialize_match(match, obfuscator_));
        }

        if (set_stack_id) {
            root_map.emplace("stack_id", owned_object::make_string(actions.stack_id));
        }
    }

    reinterpret_cast<detail::object &>(output.events) = events_array.move();
    reinterpret_cast<detail::object &>(output.actions) = serialize_actions(actions).move();
}

} // namespace ddwaf
