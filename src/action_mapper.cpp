// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <stdexcept>

#include "action_mapper.hpp"
#include "uuid.hpp"

namespace ddwaf {
action_type action_type_from_string(std::string_view type)
{
    if (type == "block_request") {
        return action_type::block_request;
    }
    if (type == "redirect_request") {
        return action_type::redirect_request;
    }
    if (type == "generate_stack") {
        return action_type::generate_stack;
    }
    if (type == "generate_schema") {
        return action_type::generate_schema;
    }
    if (type == "monitor") {
        return action_type::monitor;
    }
    // Unknown actions are valid, but provide no semantic value
    return action_type::unknown;
}

action_mapper::action_mapper() : action_by_id_(default_actions_)
{
    if (default_actions_.empty()) {
        throw std::runtime_error("empty default actions");
    }
}

// Certain versions of libc++ don't support hetereogeneous lookups using contains
template <typename T, typename Key> bool contains(T container, const Key &k)
{
    return container.find(k) != container.end();
}

void action_mapper::set_action_alias(std::string_view id, std::string alias)
{
    auto it = action_by_id_.find(id);
    if (it == action_by_id_.end()) {
        throw std::runtime_error("attempting to add alias to non existent action");
    }
    action_by_id_.emplace(std::move(alias), it->second);
}

void action_mapper::set_action(
    std::string id, std::string type, std::unordered_map<std::string, std::string> parameters)
{
    if (action_by_id_.find(id) != action_by_id_.end()) {
        // Duplicate actions might happen when a default action is overridden.
        if (default_actions_.find(id) == default_actions_.end()) {
            throw std::runtime_error("duplicate action '" + id + '\'');
        }
        auto &spec = action_by_id_[id];
        spec.type = action_type_from_string(type);
        spec.type_str = std::move(type);
        spec.parameters = std::move(parameters);
    } else {
        action_by_id_.emplace(std::move(id),
            action_spec{action_type_from_string(type), std::move(type), std::move(parameters)});
    }
}

optional_ref<const action_spec> action_mapper::get_action(std::string_view id) const
{
    auto it = action_by_id_.find(id);
    if (it == action_by_id_.end()) {
        return std::nullopt;
    }
    return {it->second};
}

[[nodiscard]] action_spec &action_mapper::get_action_ref(std::string_view id)
{
    auto it = action_by_id_.find(id);
    if (it == action_by_id_.end()) {
        throw std::out_of_range("unknown action " + std::string(id));
    }
    return {it->second};
}

const std::map<std::string, action_spec, std::less<>> action_mapper::default_actions_ = {
    {"block", {action_type::block_request, "block_request",
                  {{"status_code", "403"}, {"type", "auto"}, {"grpc_status_code", "10"}}}},
    {"stack_trace", {action_type::generate_stack, "generate_stack", {}}},
    {"extract_schema", {action_type::generate_schema, "generate_schema", {}}},
    {"monitor", {action_type::monitor, "monitor", {}}}};

} // namespace ddwaf
