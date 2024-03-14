// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <stdexcept>

#include "action_mapper.hpp"
#include "uuid.hpp"

namespace ddwaf {
namespace {
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
    if (type == "extract_schema") {
        return action_type::generate_schema;
    }
    // Unknown actions are valid, but provide no semantic value
    return action_type::unknown;
}
} // namespace

action_mapper::action_mapper()
{
    set_action("block", "block_request",
        {{"status_code", "403"}, {"type", "auto"}, {"grpc_status_code", "10"}});
    set_action("stack_trace", "generate_stack", {});
    set_action("extract_schema", "generate_schema", {});
}

void action_mapper::set_action(
    std::string id, std::string type, std::vector<std::pair<std::string, std::string>> parameters)
{
    if (action_by_id_.contains(id)) {
        throw std::runtime_error("duplicate action '" + id + '\'');
    }
    action_by_id_.emplace(std::move(id),
        action_spec{action_type_from_string(type), std::move(type), std::move(parameters)});
}

optional_ref<const action_spec> action_mapper::get_action(std::string_view id) const
{
    auto it = action_by_id_.find(id);
    if (it == action_by_id_.end()) {
        return std::nullopt;
    }
    return {it->second};
}

} // namespace ddwaf
