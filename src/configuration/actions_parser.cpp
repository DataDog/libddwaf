// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>

#include "action_mapper.hpp"
#include "builder/action_mapper_builder.hpp"
#include "configuration/actions_parser.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "log.hpp"
#include "ruleset_info.hpp"
#include "uri_utils.hpp"
#include "utils.hpp"

namespace ddwaf {

namespace {

bool validate_status_code_presence_and_type(
    auto &parameters, const std::string &key, auto &&validate_fn)
{
    auto it = parameters.find(key);
    if (it == parameters.end()) {
        return false;
    }

    // NOLINTNEXTLINE(fuchsia-trailing-return)
    auto validate_status_code = [&validate_fn](auto &&code) -> std::optional<uint64_t> {
        using T = std::decay_t<decltype(code)>;
        uint64_t ucode;
        if constexpr (std::is_same_v<T, bool>) {
            return std::nullopt;
        } else if constexpr (std::is_same_v<T, std::string>) {
            if (auto [res, value] = from_string<uint64_t>(code); res) {
                ucode = value;
            } else {
                return std::nullopt;
            }
        } else {
            ucode = static_cast<uint64_t>(code);
            if (code < 0 || static_cast<T>(ucode) != code) {
                return std::nullopt;
            }
        }
        if (ucode > 999 || !validate_fn(ucode)) {
            return std::nullopt;
        }
        return ucode;
    };

    auto &code = it->second;
    if (auto ucode = std::visit(validate_status_code, code); ucode.has_value()) {
        code = ucode.value();
        return true;
    }

    parameters.erase(it);
    return false;
}

void validate_and_add_block(auto &cfg, auto id, auto &type, auto &parameters)
{
    // Accept any status code
    auto validator = [](uint64_t /*code*/) { return true; };
    auto status_code = validate_status_code_presence_and_type(parameters, "status_code", validator);
    auto grpc_status_code =
        validate_status_code_presence_and_type(parameters, "grpc_status_code", validator);

    if (!status_code || !grpc_status_code || !parameters.contains("type")) {
        // If any of the parameters are missing, add the relevant default value
        // We could also avoid the above check ...
        auto default_params = action_mapper_builder::get_default_action("block");
        for (const auto &[k, v] : default_params.parameters) { parameters.try_emplace(k, v); }
    }

    // Validate that status codes are provided as strings

    cfg.emplace_action(std::move(id),
        action_spec{action_type_from_string(type), std::move(type), std::move(parameters)});
}

void validate_and_add_redirect(auto &cfg, auto id, auto &type, auto &parameters)
{
    auto it = parameters.find("location");
    if (it == parameters.end() || !std::holds_alternative<std::string>(it->second) ||
        std::get<std::string>(it->second).empty()) {
        auto block_params = action_mapper_builder::get_default_action("block");
        DDWAF_DEBUG("Location missing from redirect action '{}', downgrading to block_request", id);
        cfg.emplace_action(id, action_spec{.type = block_params.type,
                                   .type_str = block_params.type_str,
                                   .parameters = block_params.parameters});
        return;
    }

    // Validate the URL;
    //   - Check it's a valid URL
    //   - If it has a scheme, check it's http or https
    //   - If it doesn't have a scheme:
    //     - Check it also doesn't have an authority
    //     - Check it's a path starting with /
    auto decomposed = uri_parse(std::get<std::string>(it->second));
    if (!decomposed.has_value() ||
        (!decomposed->scheme.empty() && decomposed->scheme != "http" &&
            decomposed->scheme != "https") ||
        (decomposed->scheme_and_authority.empty() && !decomposed->path.starts_with('/'))) {
        auto block_params = action_mapper_builder::get_default_action("block");

        DDWAF_DEBUG("Unsupported scheme on redirect action '{}', downgrading to block_request", id);
        cfg.emplace_action(id, action_spec{.type = block_params.type,
                                   .type_str = block_params.type_str,
                                   .parameters = block_params.parameters});
        return;
    }

    auto validator = [](uint64_t code) {
        return code == 301 || code == 302 || code == 303 || code == 307;
    };

    if (!validate_status_code_presence_and_type(parameters, "status_code", validator)) {
        parameters.emplace("status_code", 303ULL);
    }

    cfg.emplace_action(
        id, action_spec{action_type_from_string(type), std::move(type), std::move(parameters)});
}

void remove_reserved_parameters(std::unordered_map<std::string, scalar_type> &params)
{
    // Remove any parameters considered "reserved" to avoid potential injections
    const std::array<std::string, 2> reserved{"block_id", "stack_id"};

    for (const auto &key : reserved) {
        auto it = params.find(key);
        if (it != params.end()) {
            params.erase(it);
        }
    }
}

} // namespace

void parse_actions(const raw_configuration::vector &actions_array, configuration_collector &cfg,
    ruleset_info::section_info &info)
{
    for (unsigned i = 0; i < actions_array.size(); i++) {
        const auto &node_param = actions_array[i];
        auto node = static_cast<raw_configuration::map>(node_param);

        std::string id;
        try {
            id = at<std::string>(node, "id");
            if (cfg.contains_action(id)) {
                DDWAF_WARN("Duplicate action: {}", id);
                info.add_failed(id, parser_error_severity::error, "duplicate action");
                continue;
            }

            auto type = at<std::string>(node, "type");
            auto parameters = at<std::unordered_map<std::string, scalar_type>>(node, "parameters");

            remove_reserved_parameters(parameters);

            DDWAF_DEBUG("Parsed action {} of type {}", id, type);

            // Block and redirect actions should be validated and aliased
            if (type == "redirect_request") {
                validate_and_add_redirect(cfg, id, type, parameters);
            } else if (type == "block_request") {
                validate_and_add_block(cfg, id, type, parameters);
            } else {
                cfg.emplace_action(id, action_spec{.type = action_type_from_string(type),
                                           .type_str = std::move(type),
                                           .parameters = std::move(parameters)});
            }

            info.add_loaded(std::move(id));
        } catch (const parsing_exception &e) {
            DDWAF_WARN("Failed to parse action '{}': {}", id, e.what());
            info.add_failed(i, id, e.severity(), e.what());
        } catch (const std::exception &e) {
            DDWAF_WARN("Failed to parse action '{}': {}", id, e.what());
            info.add_failed(i, id, parser_error_severity::error, e.what());
        }
    }
}

} // namespace ddwaf
