// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <cstdint>
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
#include "memory_resource.hpp"
#include "obfuscator.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "pointer.hpp"
#include "rule.hpp"
#include "serializer.hpp"
#include "uuid.hpp"

namespace ddwaf {

namespace {

owned_object serialize_match(condition_match &match, nonnull_ptr<memory::memory_resource> alloc)
{
    auto match_map = owned_object::make_map(3, alloc);

    match_map.emplace("operator", match.operator_name);
    match_map.emplace("operator_value", match.operator_value);

    auto parameters = match_map.emplace("parameters", owned_object::make_array(1, alloc));

    // Scalar case
    if (match.args.size() == 1 && match.args[0].name == "input") {
        auto param = parameters.emplace_back(owned_object::make_map(4, alloc));

        auto &arg = match.args[0];

        param.emplace("address", arg.address);
        param.emplace("value", arg.resolved.to_object(alloc));

        auto key_path =
            param.emplace("key_path", owned_object::make_array(arg.key_path.size(), alloc));
        for (const auto &key : arg.key_path) {
            if (std::holds_alternative<std::string_view>(key)) {
                key_path.emplace_back(std::get<std::string_view>(key));
            } else {
                key_path.emplace_back(std::get<int64_t>(key));
            }
        }

        auto highlight_arr =
            param.emplace("highlight", owned_object::make_array(match.highlights.size(), alloc));
        for (auto &highlight : match.highlights) {
            highlight_arr.emplace_back(highlight.to_object(alloc));
        }
    } else {
        auto param = parameters.emplace_back(owned_object::make_map(match.args.size() + 1, alloc));

        for (auto &arg : match.args) {
            auto argument = param.emplace(arg.name, owned_object::make_map(3, alloc));

            argument.emplace("address", arg.address);
            argument.emplace("value", arg.resolved.to_object(alloc));

            auto key_path =
                argument.emplace("key_path", owned_object::make_array(arg.key_path.size(), alloc));
            for (const auto &key : arg.key_path) {
                if (std::holds_alternative<std::string_view>(key)) {
                    key_path.emplace_back(std::get<std::string_view>(key));
                } else {
                    key_path.emplace_back(std::get<int64_t>(key));
                }
            }
        }

        auto highlight_arr =
            param.emplace("highlight", owned_object::make_array(match.highlights.size(), alloc));
        for (auto &highlight : match.highlights) {
            highlight_arr.emplace_back(highlight.to_object(alloc));
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

    // Block ID
    std::string block_id;

    // This set contains all remaining actions other than the blocking action
    std::unordered_set<std::string_view> non_blocking_actions;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const action_mapper &mapper;
};

action_type get_action_type(const action_mapper &mapper, std::string_view id)
{
    if (id.empty()) {
        return action_type::none;
    }

    auto it = mapper.find(id);
    if (it == mapper.end()) {
        return action_type::none;
    }

    return it->second.type;
}

void add_action_to_tracker(action_tracker &actions, std::string_view id, action_type type)
{
    if (is_blocking_action(type)) {
        if (type > actions.blocking_action_type) {
            // Only keep a single blocking action
            actions.blocking_action_type = type;
            actions.blocking_action = id;
        }

        if (actions.block_id.empty()) {
            actions.block_id = uuidv4_generate_pseudo();
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

void consolidate_actions(std::string_view action_override,
    const std::vector<std::string> &rule_actions, action_tracker &actions)
{
    if (auto type = get_action_type(actions.mapper, action_override); is_modal_action(type)) {
        // The action override must be either a blocking one or monitor
        add_action_to_tracker(actions, action_override, type);
    } else {
        // Clear the action override because it's not usable
        action_override = {};
    }

    for (const auto &action_id : rule_actions) {
        auto type = get_action_type(actions.mapper, action_id);
        if (type == action_type::none || (!action_override.empty() && is_modal_action(type))) {
            // If the rule was in monitor mode, ignore blocking and monitor actions
            continue;
        }

        add_action_to_tracker(actions, action_id, type);
    }
}

struct generated_action {
    owned_object actions_array;
    bool required_stack_id;
    bool required_block_id;
};

generated_action serialize_event_actions(std::string_view action_override,
    const std::vector<std::string> &rule_actions, action_tracker &actions,
    nonnull_ptr<memory::memory_resource> alloc)
{
    auto actions_array = owned_object::make_array(rule_actions.size(), alloc);

    bool has_block_id = false;
    if (auto type = get_action_type(actions.mapper, action_override); is_modal_action(type)) {
        // The action override must be either a blocking one or monitor
        actions_array.emplace_back(action_override);
        has_block_id = is_blocking_action(type);
    } else {
        // Without a definition, the override can't be applied
        action_override = {};
    }

    bool has_stack_id = false;
    for (const auto &action_id : rule_actions) {
        auto type = get_action_type(actions.mapper, action_id);
        if (!action_override.empty() && is_modal_action(type)) {
            // If the rule was in monitor mode, ignore blocking and monitor actions
            continue;
        }

        has_stack_id = has_stack_id || type == action_type::generate_stack;
        has_block_id = has_block_id || is_blocking_action(type);

        // If an action is unspecified, add it and move on
        actions_array.emplace_back(action_id);
    }

    return {.actions_array = std::move(actions_array),
        .required_stack_id = has_stack_id,
        .required_block_id = has_block_id};
}

void serialize_event(rule_event &event, const match_obfuscator *obfuscator,
    std::string_view action_override, const std::vector<std::string> &rule_actions,
    action_tracker &actions, borrowed_object &event_array)
{
    auto alloc = event_array.alloc();

    auto [actions_array, requires_stack_id, requires_block_id] =
        serialize_event_actions(action_override, rule_actions, actions, alloc);

    const std::size_t map_size = 2 + (requires_block_id ? 1 : 0) + (requires_stack_id ? 1 : 0);

    auto root_map = event_array.emplace_back(owned_object::make_map(map_size, alloc));

    auto rule_map = root_map.emplace("rule", owned_object::make_map(4, alloc));
    rule_map.emplace("id", event.rule.id);
    rule_map.emplace("name", event.rule.name);
    rule_map.emplace("on_match", std::move(actions_array));

    const auto &rule_tags = event.rule.tags.get();
    auto tags_map = rule_map.emplace("tags", owned_object::make_map(rule_tags.size(), alloc));
    for (const auto &[key, value] : rule_tags) { tags_map.emplace(key, value); }

    auto match_array =
        root_map.emplace("rule_matches", owned_object::make_array(event.matches.size(), alloc));
    for (auto &match : event.matches) {
        if (obfuscator != nullptr) {
            obfuscator->obfuscate_match(match);
        }
        match_array.emplace_back(serialize_match(match, alloc));
    }

    if (requires_stack_id) {
        root_map.emplace("stack_id", actions.stack_id);
    }

    if (requires_block_id) {
        root_map.emplace("security_response_id", actions.block_id);
    }
}

void serialize_action(
    std::string_view id, const action_tracker &actions, borrowed_object action_map)
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

    if (type != action_type::generate_stack) {
        auto param_map = action_map.emplace(
            type_str, owned_object::make_map(parameters.size(), action_map.alloc()));
        for (const auto &[k, v] : parameters) {
            if (std::holds_alternative<std::string>(v)) {
                param_map.emplace(k, std::get<std::string>(v));
            } else if (std::holds_alternative<bool>(v)) {
                param_map.emplace(k, std::get<bool>(v));
            } else if (std::holds_alternative<int64_t>(v)) {
                param_map.emplace(k, std::get<int64_t>(v));
            } else if (std::holds_alternative<uint64_t>(v)) {
                param_map.emplace(k, std::get<uint64_t>(v));
            } else if (std::holds_alternative<double>(v)) {
                param_map.emplace(k, std::get<double>(v));
            }
        }
        if (is_blocking_action(type)) {
            param_map.emplace("security_response_id", actions.block_id);
        }
    } else {
        auto param_map =
            action_map.emplace(type_str, owned_object::make_map(1, action_map.alloc()));
        param_map.emplace("stack_id", actions.stack_id);
    }
}

void serialize_actions(const action_tracker &actions, borrowed_object action_map)
{
    if (actions.blocking_action_type != action_type::none) {
        serialize_action(actions.blocking_action, actions, action_map);
    }

    for (const auto &id : actions.non_blocking_actions) {
        serialize_action(id, actions, action_map);
    }
}

void collect_attributes(const object_store &store, const std::vector<rule_attribute> &attributes,
    attribute_collector &collector, nonnull_ptr<memory::memory_resource> alloc)
{
    for (const auto &attr : attributes) {
        if (std::holds_alternative<rule_attribute::input_target>(attr.value_or_target)) {
            auto input = std::get<rule_attribute::input_target>(attr.value_or_target);
            collector.collect(store, input.index, input.key_path, attr.key);
        } else if (std::holds_alternative<std::string>(attr.value_or_target)) {
            collector.insert(attr.key, std::get<std::string>(attr.value_or_target), alloc);
        } else if (std::holds_alternative<uint64_t>(attr.value_or_target)) {
            collector.insert(attr.key, std::get<uint64_t>(attr.value_or_target));
        } else if (std::holds_alternative<int64_t>(attr.value_or_target)) {
            collector.insert(attr.key, std::get<int64_t>(attr.value_or_target));
        } else if (std::holds_alternative<double>(attr.value_or_target)) {
            collector.insert(attr.key, std::get<double>(attr.value_or_target));
        } else if (std::holds_alternative<bool>(attr.value_or_target)) {
            collector.insert(attr.key, std::get<bool>(attr.value_or_target));
        }
    }
}

} // namespace

void result_serializer::serialize(const object_store &store, std::vector<rule_result> &results,
    attribute_collector &collector, const timer &deadline, result_components output)
{
    action_tracker actions{.blocking_action = {},
        .stack_id = {},
        .block_id = {},
        .non_blocking_actions = {},
        .mapper = actions_};

    // First collect any pending attributes from previous runs
    collector.collect_pending(store);

    bool final_keep = false;
    for (auto &result : results) {
        final_keep |= result.keep;

        // Action consolidation should happen before event serialisation to
        // ensure that any relevant IDs are generated (once).
        consolidate_actions(result.action_override, result.actions, actions);

        if (result.event) {
            serialize_event(result.event.value(), obfuscator_, result.action_override,
                result.actions, actions, output.events);
        }

        collect_attributes(store, result.attributes.get(), collector, alloc_);
    }

    // Using the interface functions would replace the key contained within the
    // object. This will not be an issue in v2.
    output.duration = owned_object::make_unsigned(deadline.elapsed().count());
    output.timeout = owned_object{deadline.expired_before()};
    output.keep = owned_object{final_keep};
    output.attributes = collector.get_available_attributes_and_reset();
    serialize_actions(actions, output.actions);
}

std::pair<owned_object, result_components> result_serializer::initialise_result_object()
{
    auto object =
        object_builder::map({{"events", object_builder::array({}, alloc_)},
                                {"actions", object_builder::map({}, alloc_)},
                                {"duration", owned_object::make_unsigned(0)}, {"timeout", false},
                                {"attributes", object_builder::map({}, alloc_)}, {"keep", false}},
            alloc_);

    const result_components res{.events = object.at(0),
        .actions = object.at(1),
        .duration = object.at(2),
        .timeout = object.at(3),
        .attributes = object.at(4),
        .keep = object.at(5)};

    return {std::move(object), res};
}

} // namespace ddwaf
