// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "action_mapper.hpp"
#include "log.hpp"
#include "parameter.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"
#include "uri_utils.hpp"
#include <exception>
#include <memory>
#include <string>
#include <unordered_map>

namespace ddwaf::parser::v2 {

void validate_and_add_block(auto &id, auto &type, auto &parameters, action_mapper_builder &builder)
{
    if (!parameters.contains("status_code") || !parameters.contains("grpc_status_code") ||
        !parameters.contains("type")) {
        // If any of the parameters are missing, add the relevant default value
        // We could also avoid the above check ...
        auto default_params = action_mapper_builder::get_default_action("block");
        for (const auto &[k, v] : default_params.parameters) { parameters.try_emplace(k, v); }
    }
    builder.set_action(id, std::move(type), std::move(parameters));
}

void validate_and_add_redirect(
    auto &id, auto &type, auto &parameters, action_mapper_builder &builder)
{
    auto it = parameters.find("location");
    if (it == parameters.end() || it->second.empty()) {
        builder.alias_default_action_to("block", id);
        return;
    }

    // Validate the URL;
    //   - Check it's a valid URL
    //   - If it has a scheme, check it's http or https
    //   - If it doesn't have a scheme:
    //     - Check it also doesn't have an authority
    //     - Check it's a path starting with /
    auto decomposed = uri_parse(it->second);
    if (!decomposed.has_value() ||
        (!decomposed->scheme.empty() && decomposed->scheme != "http" &&
            decomposed->scheme != "https") ||
        (decomposed->scheme_and_authority.empty() && !decomposed->path.starts_with('/'))) {
        builder.alias_default_action_to("block", id);
        return;
    }

    it = parameters.find("status_code");
    if (it != parameters.end()) {
        auto [res, code] = ddwaf::from_string<unsigned>(it->second);
        if (!res || (code != 301 && code != 302 && code != 303 && code != 307)) {
            it->second = "303";
        }
    } else {
        parameters.emplace("status_code", "303");
    }

    builder.set_action(id, std::move(type), std::move(parameters));
}

std::shared_ptr<action_mapper> parse_actions(
    parameter::vector &actions_array, base_section_info &info)
{
    action_mapper_builder builder;

    for (unsigned i = 0; i < actions_array.size(); i++) {
        const auto &node_param = actions_array[i];
        auto node = static_cast<parameter::map>(node_param);

        std::string id;
        try {
            id = at<std::string>(node, "id");
            auto type = at<std::string>(node, "type");
            auto parameters = at<std::unordered_map<std::string, std::string>>(node, "parameters");

            DDWAF_DEBUG("Parsed action {} of type {}", id, type);

            // Block and redirect actions should be validated and aliased
            if (type == "redirect_request") {
                validate_and_add_redirect(id, type, parameters, builder);
            } else if (type == "block_request") {
                validate_and_add_block(id, type, parameters, builder);
            } else {
                builder.set_action(id, std::move(type), std::move(parameters));
            }

            info.add_loaded(id);
        } catch (const std::exception &e) {
            if (id.empty()) {
                id = index_to_id(i);
            }
            DDWAF_WARN("Failed to parse action '{}': {}", id, e.what());
            info.add_failed(id, e.what());
        }
    }

    return builder.build_shared();
}

} // namespace ddwaf::parser::v2
