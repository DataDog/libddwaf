// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <iostream>
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

ddwaf_object *to_object(ddwaf_object &tmp, std::string_view str, bool redact = false)
{
    if (redact) {
        return ddwaf_object_stringl(
            &tmp, ddwaf::obfuscator::redaction_msg.data(), ddwaf::obfuscator::redaction_msg.size());
    }
    return ddwaf_object_stringl(&tmp, str.data(), str.size());
}

void serialize_match(const condition_match &match, ddwaf_object &match_map, auto &obfuscator)
{
    ddwaf_object tmp;
    ddwaf_object param;
    ddwaf_object_map(&param);

    bool redact = redact_match(obfuscator, match);

    ddwaf_object highlight_arr;
    ddwaf_object_array(&highlight_arr);
    for (const auto &highlight : match.highlights) {
        ddwaf_object_array_add(&highlight_arr, to_object(tmp, highlight, redact));
    }

    // Scalar case
    if (match.args.size() == 1 || match.args[0].name == "input") {
        const auto &arg = match.args[0];

        ddwaf_object key_path;
        ddwaf_object_array(&key_path);
        for (const auto &key : arg.key_path) {
            ddwaf_object_array_add(&key_path, to_object(tmp, key));
        }

        ddwaf_object_map_add(&param, "address", to_object(tmp, arg.address));
        ddwaf_object_map_add(&param, "key_path", &key_path);
        ddwaf_object_map_add(&param, "value", to_object(tmp, arg.resolved, redact));
    } else {
        for (const auto &arg : match.args) {
            ddwaf_object argument;
            ddwaf_object_map(&argument);

            ddwaf_object key_path;
            ddwaf_object_array(&key_path);
            for (const auto &key : arg.key_path) {
                ddwaf_object_array_add(&key_path, to_object(tmp, key));
            }

            ddwaf_object_map_add(&argument, "address", to_object(tmp, arg.address));
            ddwaf_object_map_add(&argument, "key_path", &key_path);
            ddwaf_object_map_add(&argument, "value", to_object(tmp, arg.resolved, redact));

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

struct action_tracker {
    // The blocking action refers to either a block_request or redirect_request
    // action, the latter having precedence over the former.
    std::string_view blocking_action;
    action_type blocking_action_type{action_type::none};

    // Stack trace ID
    std::string stack_id;

    std::unordered_set<std::string_view> all;

    const action_mapper &mapper;
};

void serialize_rule(const ddwaf::rule &rule, action_type action_override, ddwaf_object &rule_map,
    action_tracker &actions)
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

    const auto &rule_actions = rule.get_actions();
    if (!rule_actions.empty()) {
        ddwaf_object actions_array;
        ddwaf_object_array(&actions_array);

        for (const auto &id : rule_actions) {
            auto spec = actions.mapper.get_action(id);
            if (!spec) {
                // If an action is unspecified, add it and move on
                ddwaf_object_array_add(&actions_array, to_object(tmp, id));
                continue;
            }

            const auto &[type, type_str, parameters] = spec->get();
            if (action_override == action_type::monitor &&
                (type == action_type::monitor || is_blocking_action(type))) {
                // If the rule was in monitor mode, ignore blocking and monitor actions
                continue;
            }

            if (is_blocking_action(type)) {
                // Only keep a single blocking action
                if (type > actions.blocking_action_type) {
                    actions.blocking_action_type = type;
                    actions.blocking_action = id;
                }
            } else {
                if (type == action_type::generate_stack) {
                    // Stack trace actions require a dynamic stack ID, however we
                    // only provide a single stack ID per run
                    if (actions.stack_id.empty()) {
                        actions.stack_id = uuidv4_generate_pseudo();
                    }
                }

                actions.all.emplace(id);
            }

            ddwaf_object_array_add(&actions_array, to_object(tmp, id));
        }

        if (action_override == action_type::monitor) {
            ddwaf_object_array_add(&actions_array, to_object(tmp, "monitor"));
        }
        ddwaf_object_map_add(&rule_map, "on_match", &actions_array);
    }
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

void serialize_action(std::string_view id, ddwaf_object &action_map, const action_tracker &actions)
{
    auto spec = actions.mapper.get_action(id);
    if (!spec) {
        // If the action has no spec, we don't report it
        return;
    }

    const auto &[type, type_str, parameters] = spec->get();
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

} // namespace

void event_serializer::serialize(const std::vector<event> &events, ddwaf_result &output) const
{
    if (events.empty()) {
        return;
    }

    action_tracker actions{.mapper = actions_};

    ddwaf_object_array(&output.events);
    for (const auto &event : events) {
        ddwaf_object root_map;
        ddwaf_object rule_map;
        ddwaf_object match_array;

        ddwaf_object_map(&root_map);
        ddwaf_object_array(&match_array);

        if (event.rule != nullptr) {
            serialize_rule(*event.rule, event.action_override, rule_map, actions);
        } else {
            // This will only be used for testing
            serialize_empty_rule(rule_map);
        }

        for (const auto &match : event.matches) {
            ddwaf_object match_map;
            ddwaf_object_map(&match_map);
            serialize_match(match, match_map, obfuscator_);
            ddwaf_object_array_add(&match_array, &match_map);
        }

        ddwaf_object_map_add(&root_map, "rule", &rule_map);
        ddwaf_object_map_add(&root_map, "rule_matches", &match_array);

        ddwaf_object_array_add(&output.events, &root_map);
    }

    ddwaf_object_map(&output.actions);

    if (actions.blocking_action_type != action_type::none) {
        serialize_action(actions.blocking_action, output.actions, actions);
    }

    for (const auto &id : actions.all) { serialize_action(id, output.actions, actions); }
}

} // namespace ddwaf
