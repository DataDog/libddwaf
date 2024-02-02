// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <unordered_set>

#include "ddwaf.h"
#include "event.hpp"
#include "rule.hpp"

namespace ddwaf {

namespace {

bool redact_match(const ddwaf::obfuscator &obfuscator, const event::univariate_match &match)
{
    for (const auto &key : match.key_path) {
        if (obfuscator.is_sensitive_key(key)) {
            return true;
        }
    }

    return obfuscator.is_sensitive_value(match.resolved) ||
           obfuscator.is_sensitive_value(match.matched);
}

bool redact_match(const ddwaf::obfuscator &obfuscator, const event::multivariate_match &match)
{
    return false;
}

bool redact_match(const ddwaf::obfuscator & /*obfuscator*/, const std::monostate & /*match*/)
{
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

void serialize_match(const event::univariate_match &match, ddwaf_object &match_map, bool redact)
{
    ddwaf_object tmp;
    ddwaf_object key_path;
    ddwaf_object_array(&key_path);
    for (const auto &key : match.key_path) {
        ddwaf_object_array_add(&key_path, to_object(tmp, key));
    }

    ddwaf_object highlight;
    ddwaf_object_array(&highlight);
    if (!match.matched.empty()) {
        ddwaf_object_array_add(&highlight, to_object(tmp, match.matched, redact));
    }

    ddwaf_object param;
    ddwaf_object_map(&param);
    ddwaf_object_map_add(&param, "address", to_object(tmp, match.address));
    ddwaf_object_map_add(&param, "key_path", &key_path);
    ddwaf_object_map_add(&param, "value", to_object(tmp, match.resolved, redact));
    ddwaf_object_map_add(&param, "highlight", &highlight);

    ddwaf_object parameters;
    ddwaf_object_array(&parameters);
    ddwaf_object_array_add(&parameters, &param);

    ddwaf_object_map_add(&match_map, "operator", to_object(tmp, match.operator_name));
    ddwaf_object_map_add(&match_map, "operator_value", to_object(tmp, match.operator_value));
    ddwaf_object_map_add(&match_map, "parameters", &parameters);
}

void serialize_match(const event::multivariate_match &match, ddwaf_object &match_map, bool redact)
{
    ddwaf_object tmp;
    ddwaf_object param;
    ddwaf_object_map(&param);

    for (const auto &arg : match.arguments) {
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

    ddwaf_object highlight;
    ddwaf_object_array(&highlight);
    if (!match.matched.empty()) {
        ddwaf_object_array_add(&highlight, to_object(tmp, match.matched, redact));
    }

    ddwaf_object_map_add(&param, "highlight", &highlight);

    ddwaf_object parameters;
    ddwaf_object_array(&parameters);
    ddwaf_object_array_add(&parameters, &param);

    ddwaf_object_map_add(&match_map, "operator", to_object(tmp, match.operator_name));
    ddwaf_object_map_add(&match_map, "operator_value", to_object(tmp, match.operator_value));
    ddwaf_object_map_add(&match_map, "parameters", &parameters);
}

void serialize_match(
    const std::monostate & /*match*/, ddwaf_object & /*match_map*/, bool /*redact*/)
{
    throw std::runtime_error("invalid match found during serialisation");
}

} // namespace

void event_serializer::serialize(const std::vector<event> &events, ddwaf_result &output) const
{
    ddwaf_object tmp;

    if (events.empty()) {
        return;
    }

    ddwaf_object_array(&output.events);
    ddwaf_object_array(&output.actions);

    std::unordered_set<std::string_view> all_actions;
    for (const auto &event : events) {
        ddwaf_object root_map;
        ddwaf_object rule_map;
        ddwaf_object tags_map;
        ddwaf_object match_array;

        ddwaf_object_map(&root_map);
        ddwaf_object_map(&rule_map);
        ddwaf_object_map(&tags_map);
        ddwaf_object_array(&match_array);

        if (event.rule != nullptr) {
            for (const auto &[key, value] : event.rule->get_tags()) {
                ddwaf_object_map_addl(&tags_map, key.c_str(), key.size(), to_object(tmp, value));
            }

            ddwaf_object_map_add(&rule_map, "id", to_object(tmp, event.rule->get_id()));
            ddwaf_object_map_add(&rule_map, "name", to_object(tmp, event.rule->get_name()));

            const auto &actions = event.rule->get_actions();
            if (!actions.empty()) {
                ddwaf_object actions_array;
                ddwaf_object_array(&actions_array);
                if (!event.skip_actions) {
                    for (const auto &action : actions) {
                        all_actions.emplace(action);
                        ddwaf_object_array_add(&actions_array, to_object(tmp, action));
                    }
                } else {
                    ddwaf_object_array_add(&actions_array, to_object(tmp, "monitor"));
                }
                ddwaf_object_map_add(&rule_map, "on_match", &actions_array);
            }
        } else {
            // This will only be used for testing
            ddwaf_object_map_add(&rule_map, "id", to_object(tmp, ""));
            ddwaf_object_map_add(&rule_map, "name", to_object(tmp, ""));
            ddwaf_object_map_add(&tags_map, "type", to_object(tmp, ""));
            ddwaf_object_map_add(&tags_map, "category", to_object(tmp, ""));
        }
        ddwaf_object_map_add(&rule_map, "tags", &tags_map);

        for (const auto &match : event.matches) {
            const bool redact =
                std::visit([&](auto &&arg) { return redact_match(obfuscator_, arg); }, match);

            ddwaf_object match_map;
            ddwaf_object_map(&match_map);
            std::visit([&](auto &&arg) { serialize_match(arg, match_map, redact); }, match);

            ddwaf_object_array_add(&match_array, &match_map);
        }

        ddwaf_object_map_add(&root_map, "rule", &rule_map);
        ddwaf_object_map_add(&root_map, "rule_matches", &match_array);

        ddwaf_object_array_add(&output.events, &root_map);
    }

    if (!all_actions.empty()) {
        for (const auto &action : all_actions) {
            ddwaf_object string_action;
            ddwaf_object_stringl(&string_action, action.data(), action.size());
            ddwaf_object_array_add(&output.actions, &string_action);
        }
    }
}

} // namespace ddwaf
