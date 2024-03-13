// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/actions_parser.hpp"
#include "log.hpp"
#include "parser/common.hpp"

namespace ddwaf::parser::v2 {

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

    // Unknown actions are valid, but provide no semantic value
    return action_type::unknown;
}

std::shared_ptr<action_mapper> parse_actions(
    parameter::vector &actions_array, base_section_info &info)
{
    action_mapper actions;

    for (unsigned i = 0; i < actions_array.size(); i++) {
        const auto &node_param = actions_array[i];
        auto node = static_cast<parameter::map>(node_param);

        std::string_view id;
        try {
            id = at<std::string_view>(node, "id");
            auto type = at<std::string_view>(node, "type");
            auto parameters = at<std::unordered_map<std::string, std::string>>(node, "parameters");

            DDWAF_DEBUG("Parsed action {} of type {}", id, type);
            actions.set_action(
                std::string{id}, action_type_from_string(type), std::move(parameters));
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
