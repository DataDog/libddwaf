// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <stdexcept>

#include "action_mapper.hpp"
#include "uuid.hpp"

namespace ddwaf {
action_mapper::action_mapper()
{
    set_action("block", action_type::block_request,
        {{"status_code", "403"}, {"type", "auto"}, {"grpc_status_code", "10"}});
    set_action("stack_trace", action_type::generate_stack, {});
}

void action_mapper::set_action(
    std::string id, action_type type, std::unordered_map<std::string, std::string> parameters)
{
    if (action_by_id_.contains(id)) {
        throw std::runtime_error("duplicate action '" + id + '\'');
    }
    action_by_id_.emplace(std::move(id), action_spec{type, std::move(parameters)});
}

optional_ref<const action_spec> action_mapper::get_action(const std::string &id) const
{
    auto it = action_by_id_.find(id);
    if (it == action_by_id_.end()) {
        return std::nullopt;
    }

    return {it->second};
}

} // namespace ddwaf
