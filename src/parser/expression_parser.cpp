// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/lfi_detector.hpp"
#include "condition/scalar_condition.hpp"
#include "condition/sqli_detector.hpp"
#include "condition/ssrf_detector.hpp"
#include "expression.hpp"
#include "parser/common.hpp"
#include "parser/parser.hpp"
#include <memory>

namespace ddwaf::parser::v2 {

namespace {

template <typename T>
std::vector<condition_parameter> parse_arguments(const parameter::map &params, data_source source,
    const std::vector<transformer_id> &transformers, address_container &addresses)
{
    const auto &specification = T::arguments();
    std::vector<condition_parameter> definitions;

    definitions.reserve(specification.size());

    for (const auto spec : specification) {
        definitions.emplace_back();
        condition_parameter &def = definitions.back();

        auto inputs = at<parameter::vector>(params, spec.name);
        if (inputs.empty()) {
            if (!spec.optional) {
                throw ddwaf::parsing_error("empty non-optional argument");
            }
            continue;
        }

        if (!spec.variadic && inputs.size() > 1) {
            throw ddwaf::parsing_error("multiple targets for non-variadic argument");
        }

        auto &targets = def.targets;
        for (const auto &input_param : inputs) {
            auto input = static_cast<parameter::map>(input_param);
            auto address = at<std::string>(input, "address");

            DDWAF_DEBUG("Found address {}", address);

            if (address.empty()) {
                throw ddwaf::parsing_error("empty address");
            }

            auto kp = at<std::vector<std::string>>(input, "key_path", {});
            for (const auto &path : kp) {
                if (path.empty()) {
                    throw ddwaf::parsing_error("empty key_path");
                }
            }

            addresses.required.emplace(address);
            auto it = input.find("transformers");
            if (it == input.end()) {
                targets.emplace_back(condition_target{
                    address, get_target_index(address), std::move(kp), transformers, source});
            } else {
                auto input_transformers = static_cast<parameter::vector>(it->second);
                source = data_source::values;
                auto new_transformers = parse_transformers(input_transformers, source);
                targets.emplace_back(condition_target{address, get_target_index(address),
                    std::move(kp), std::move(new_transformers), source});
            }
        }
    }

    return definitions;
}

} // namespace

std::shared_ptr<expression> parse_expression(const parameter::vector &conditions_array,
    std::unordered_map<std::string, std::string> &data_ids, data_source source,
    const std::vector<transformer_id> &transformers, address_container &addresses,
    const object_limits &limits)
{
    std::vector<std::unique_ptr<base_condition>> conditions;
    for (const auto &cond_param : conditions_array) {
        auto root = static_cast<parameter::map>(cond_param);

        auto operator_name = at<std::string_view>(root, "operator");
        auto params = at<parameter::map>(root, "parameters");

        if (operator_name == "lfi_detector") {
            auto arguments = parse_arguments<lfi_detector>(params, source, transformers, addresses);
            conditions.emplace_back(std::make_unique<lfi_detector>(std::move(arguments), limits));
        } else if (operator_name == "ssrf_detector") {
            auto arguments =
                parse_arguments<ssrf_detector>(params, source, transformers, addresses);
            conditions.emplace_back(std::make_unique<ssrf_detector>(std::move(arguments), limits));
        } else if (operator_name == "sqli_detector") {
            auto arguments =
                parse_arguments<sqli_detector>(params, source, transformers, addresses);
            conditions.emplace_back(std::make_unique<sqli_detector>(std::move(arguments), limits));
        } else {
            auto [data_id, matcher] = parse_matcher(operator_name, params);

            if (!matcher && !data_id.empty()) {
                data_ids.emplace(data_id, operator_name);
            }

            auto arguments =
                parse_arguments<scalar_condition>(params, source, transformers, addresses);

            conditions.emplace_back(std::make_unique<scalar_condition>(
                std::move(matcher), data_id, std::move(arguments), limits));
        }
    }

    return std::make_shared<expression>(std::move(conditions));
}

std::shared_ptr<expression> parse_simplified_expression(const parameter::vector &conditions_array,
    address_container &addresses, const object_limits &limits)
{
    std::unordered_map<std::string, std::string> data_ids;
    return parse_expression(conditions_array, data_ids, data_source::values, {}, addresses, limits);
}

} // namespace ddwaf::parser::v2
