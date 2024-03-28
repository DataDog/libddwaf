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

void action_mapper_builder::alias_default_action_to(std::string_view default_id, std::string alias)
{
    auto it = default_actions_.find(default_id);
    if (it == default_actions_.end()) {
        throw std::runtime_error(
            "attempting to add alias to non-existent default action " + std::string(default_id));
    }
    action_by_id_.emplace(std::move(alias), it->second);
}

void action_mapper_builder::set_action(
    std::string id, std::string type, std::unordered_map<std::string, std::string> parameters)
{
    if (action_by_id_.find(id) != action_by_id_.end()) {
        throw std::runtime_error("duplicate action '" + id + '\'');
    }

    action_by_id_.emplace(std::move(id),
        action_spec{action_type_from_string(type), std::move(type), std::move(parameters)});
}

[[nodiscard]] const action_spec &action_mapper_builder::get_default_action(std::string_view id)
{
    auto it = default_actions_.find(id);
    if (it == default_actions_.end()) {
        throw std::out_of_range("unknown action " + std::string(id));
    }
    return it->second;
}

std::shared_ptr<action_mapper> action_mapper_builder::build_shared()
{
    return std::make_shared<action_mapper>(build());
}

action_mapper action_mapper_builder::build()
{
    for (const auto &[action_id, action_spec] : default_actions_) {
        action_by_id_.try_emplace(action_id, action_spec);
    }

    return std::move(action_by_id_);
}

const std::map<std::string, action_spec, std::less<>> action_mapper_builder::default_actions_ = {
    {"block", {action_type::block_request, "block_request",
                  {{"status_code", "403"}, {"type", "auto"}, {"grpc_status_code", "10"}}}},
    {"stack_trace", {action_type::generate_stack, "generate_stack", {}}},
    {"extract_schema", {action_type::generate_schema, "generate_schema", {}}},
    {"monitor", {action_type::monitor, "monitor", {}}}};

} // namespace ddwaf
