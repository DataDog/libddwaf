// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "condition/base.hpp"
#include "condition/cmdi_detector.hpp"
#include "condition/exists.hpp"
#include "condition/lfi_detector.hpp"
#include "condition/scalar_condition.hpp"
#include "condition/shi_detector.hpp"
#include "condition/sqli_detector.hpp"
#include "condition/ssrf_detector.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/expression_parser.hpp"
#include "configuration/common/matcher_parser.hpp"
#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "configuration/common/transformer_parser.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "matcher/equals.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/greater_than.hpp"
#include "matcher/hidden_ascii_match.hpp"
#include "matcher/ip_match.hpp"
#include "matcher/is_sqli.hpp"
#include "matcher/is_xss.hpp"
#include "matcher/lower_than.hpp"
#include "matcher/phrase_match.hpp"
#include "matcher/regex_match.hpp"
#include "target_address.hpp"
#include "transformer/base.hpp"
#include "utils.hpp"

namespace ddwaf {

namespace {

template <typename T>
std::vector<condition_parameter> parse_arguments(const raw_configuration::map &params,
    data_source source, const std::vector<transformer_id> &transformers)
{
    const auto &specification = T::arguments();
    std::vector<condition_parameter> definitions;

    definitions.reserve(specification.size());

    for (const auto spec : specification) {
        definitions.emplace_back();
        condition_parameter &def = definitions.back();

        auto inputs = at<raw_configuration::vector>(params, spec.name);
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
            auto input = static_cast<raw_configuration::map>(input_param);
            auto address = at<std::string>(input, "address");

            DDWAF_DEBUG("Found address {}", address);

            if (address.empty()) {
                throw ddwaf::parsing_error("empty address");
            }

            auto kp = at<std::vector<std::string>>(input, "key_path", {});
            if (kp.size() > object_limits::max_key_path_depth) {
                throw ddwaf::parsing_error("key_path beyond maximum container depth");
            }

            for (const auto &path : kp) {
                if (path.empty()) {
                    throw ddwaf::parsing_error("empty key_path");
                }
            }

            auto it = input.find("transformers");
            if (it == input.end()) {
                targets.emplace_back(condition_target{.name = address,
                    .index = get_target_index(address),
                    .key_path = std::move(kp),
                    .transformers = transformers,
                    .source = source});
            } else {
                auto input_transformers = static_cast<raw_configuration::vector>(it->second);
                if (input_transformers.size() > object_limits::max_transformers_per_address) {
                    throw ddwaf::parsing_error("number of transformers beyond allowed limit");
                }

                source = data_source::values;
                auto new_transformers = parse_transformers(input_transformers, source);
                targets.emplace_back(condition_target{.name = address,
                    .index = get_target_index(address),
                    .key_path = std::move(kp),
                    .transformers = std::move(new_transformers),
                    .source = source});
            }
        }
    }

    return definitions;
}

template <typename T, typename... Matchers>
auto build_condition(std::string_view operator_name, const raw_configuration::map &params,
    data_source source, const std::vector<transformer_id> &transformers)
{
    auto [data_id, matcher] = parse_matcher<Matchers...>(operator_name, params);
    auto arguments = parse_arguments<T>(params, source, transformers);
    return std::make_unique<T>(std::move(matcher), data_id, std::move(arguments));
}

template <typename Condition>
auto build_versioned_condition(std::string_view operator_name, unsigned version,
    const raw_configuration::map &params, data_source source,
    const std::vector<transformer_id> &transformers)
{
    if (version > Condition::version) {
        throw unsupported_operator_version(operator_name, version, Condition::version);
    }

    auto arguments = parse_arguments<Condition>(params, source, transformers);
    return std::make_unique<Condition>(std::move(arguments));
}

} // namespace

std::shared_ptr<expression> parse_expression(const raw_configuration::vector &conditions_array,
    data_source source, const std::vector<transformer_id> &transformers)
{
    std::vector<std::unique_ptr<base_condition>> conditions;
    for (const auto &cond_param : conditions_array) {
        auto root = static_cast<raw_configuration::map>(cond_param);

        auto operator_name = at<std::string_view>(root, "operator");
        auto params = at<raw_configuration::map>(root, "parameters");

        // Exploit Prevention Operators may have a single-digit version
        unsigned version = 0;
        auto version_idx = operator_name.find("@v");
        if (version_idx != std::string_view::npos) {
            auto version_str = operator_name.substr(version_idx + 2);
            auto [res, value] = from_string<unsigned>(version_str);
            if (res) {
                version = value;
            }
            operator_name = operator_name.substr(0, version_idx);
        }

        if (operator_name == "lfi_detector") {
            conditions.emplace_back(build_versioned_condition<lfi_detector>(
                operator_name, version, params, source, transformers));
        } else if (operator_name == "ssrf_detector") {
            conditions.emplace_back(build_versioned_condition<ssrf_detector>(
                operator_name, version, params, source, transformers));
        } else if (operator_name == "sqli_detector") {
            conditions.emplace_back(build_versioned_condition<sqli_detector>(
                operator_name, version, params, source, transformers));
        } else if (operator_name == "shi_detector") {
            conditions.emplace_back(build_versioned_condition<shi_detector>(
                operator_name, version, params, source, transformers));
        } else if (operator_name == "cmdi_detector") {
            conditions.emplace_back(build_versioned_condition<cmdi_detector>(
                operator_name, version, params, source, transformers));
        } else if (operator_name == "exists") {
            auto arguments = parse_arguments<exists_condition>(params, source, transformers);
            conditions.emplace_back(std::make_unique<exists_condition>(std::move(arguments)));
        } else if (operator_name == "!exists") {
            auto arguments =
                parse_arguments<exists_negated_condition>(params, source, transformers);
            conditions.emplace_back(
                std::make_unique<exists_negated_condition>(std::move(arguments)));
        } else if (operator_name.starts_with('!')) {
            conditions.emplace_back(
                build_condition<scalar_negated_condition, matcher::ip_match, matcher::exact_match,
                    matcher::regex_match, matcher::phrase_match, matcher::equals<>>(
                    operator_name.substr(1), params, source, transformers));
        } else {
            conditions.emplace_back(build_condition<scalar_condition, matcher::equals<>,
                matcher::exact_match, matcher::greater_than<>, matcher::ip_match, matcher::is_sqli,
                matcher::is_xss, matcher::lower_than<>, matcher::phrase_match, matcher::regex_match,
                matcher::hidden_ascii_match>(operator_name, params, source, transformers));
        }
    }

    return std::make_shared<expression>(std::move(conditions));
}

std::shared_ptr<expression> parse_simplified_expression(
    const raw_configuration::vector &conditions_array)
{
    return parse_expression(conditions_array, data_source::values, {});
}

} // namespace ddwaf
