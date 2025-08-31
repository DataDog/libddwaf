// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "action_mapper.hpp"
#include "builder/action_mapper_builder.hpp"
#include "utils.hpp"

namespace ddwaf {

void action_mapper_builder::set_action(const std::string &id, std::string type,
    std::unordered_map<std::string, scalar_type> parameters)
{
    auto [it, res] =
        action_by_id_.try_emplace(id, action_parameters{.type = action_type_from_string(type),
                                          .type_str = std::move(type),
                                          .parameters = std::move(parameters)});
    if (!res) {
        throw std::runtime_error("duplicate action '" + id + '\'');
    }
}

[[nodiscard]] const action_parameters &action_mapper_builder::get_default_action(
    std::string_view id)
{
    auto it = default_actions_.find(id);
    if (it == default_actions_.end()) {
        throw std::out_of_range("unknown action " + std::string(id));
    }
    return it->second;
}

std::shared_ptr<const action_mapper> action_mapper_builder::build_shared()
{
    return std::make_shared<const action_mapper>(build());
}

action_mapper action_mapper_builder::build()
{
    for (const auto &[action_id, action_parameters] : default_actions_) {
        action_by_id_.try_emplace(action_id, action_parameters);
    }

    return std::move(action_by_id_);
}

const std::map<std::string, action_parameters, std::less<>>
    action_mapper_builder::default_actions_ = {
        {"block", {.type = action_type::block_request,
                      .type_str = "block_request",
                      .parameters = {{"status_code", 403ULL}, {"type", "auto"},
                          {"grpc_status_code", 10ULL}}}},
        {"stack_trace",
            {.type = action_type::generate_stack, .type_str = "generate_stack", .parameters = {}}},
        {"extract_schema", {.type = action_type::generate_schema,
                               .type_str = "generate_schema",
                               .parameters = {}}},
        {"monitor", {.type = action_type::monitor, .type_str = "monitor", .parameters = {}}}};

} // namespace ddwaf
