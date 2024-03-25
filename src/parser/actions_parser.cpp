// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "log.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"

namespace ddwaf::parser::v2 {

void validate_and_add_block(auto &id, auto &type, auto &parameters, action_mapper &actions)
{
    if (!parameters.contains("status_code") || !parameters.contains("grpc_status_code") ||
        !parameters.contains("type")) {
        // If any of the parameters are missing, add the relevant default value
        // We could also avoid the above check ...
        auto default_params = actions.get_action_ref("block");
        for (const auto &[k, v] : default_params.parameters) { parameters.try_emplace(k, v); }
    }
    actions.set_action(id, std::move(type), std::move(parameters));
}

void validate_and_add_redirect(auto &id, auto &type, auto &parameters, action_mapper &actions)
{
    auto it = parameters.find("location");
    if (it == parameters.end() || it->second.empty()) {
        actions.set_action_alias("block", id);
        return;
    }

    it = parameters.find("status_code");
    if (it != parameters.end()) {
        auto [res, code] = ddwaf::from_string<unsigned>(it->second);
        if (!res || code < 300 || code > 399) {
            it->second = "303";
        }
    } else {
        parameters.emplace("status_code", "303");
    }

    actions.set_action(id, std::move(type), std::move(parameters));
}

std::shared_ptr<action_mapper> parse_actions(
    parameter::vector &actions_array, base_section_info &info)
{
    action_mapper actions;

    for (unsigned i = 0; i < actions_array.size(); i++) {
        const auto &node_param = actions_array[i];
        auto node = static_cast<parameter::map>(node_param);

        std::string id;
        try {
            id = at<std::string>(node, "id");
            auto type = at<std::string>(node, "type");
            auto parameters = at<std::unordered_map<std::string, std::string>>(node, "parameters");

            // Block and redirect actions should be validated and aliased
            if (type == "redirect_request") {
                validate_and_add_redirect(id, type, parameters, actions);
            } else if (type == "block_request") {
                validate_and_add_block(id, type, parameters, actions);
            } else {
                actions.set_action(id, std::move(type), std::move(parameters));
            }

            DDWAF_DEBUG("Parsed action {} of type {}", id, type);
            info.add_loaded(id);
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse action '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }

    return std::make_shared<action_mapper>(std::move(actions));
}

} // namespace ddwaf::parser::v2
