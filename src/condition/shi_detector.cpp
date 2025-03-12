// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/shi_common.hpp"
#include "condition/shi_detector.hpp"
#include "condition/structured_condition.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "object_type.hpp"
#include "object_view.hpp"
#include "tokenizer/shell.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

eval_result shi_detector::eval_string(const unary_argument<object_view> &resource,
    const variadic_argument<object_view> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    if (resource.value.empty()) {
        return {};
    }

    auto resource_sv = resource.value.as<std::string_view>();

    std::vector<shell_token> resource_tokens;
    for (const auto &param : params) {
        auto res = find_shi_from_params(
            resource_sv, resource_tokens, param.value, objects_excluded, limits, deadline);
        if (res.has_value()) {
            const std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            const bool ephemeral = resource.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match = condition_match{.args = {{.name = "resource"sv,
                                                       .resolved = std::string{resource_sv},
                                                       .address = resource.address,
                                                       .key_path = resource_kp},
                                              {.name = "params"sv,
                                                  .resolved = highlight,
                                                  .address = param.address,
                                                  .key_path = param_kp}},
                .highlights = {std::move(highlight)},
                .operator_name = "shi_detector",
                .operator_value = {},
                .ephemeral = ephemeral};

            return {.outcome = true, .ephemeral = ephemeral};
        }
    }

    return {};
}

eval_result shi_detector::eval_array(const unary_argument<object_view> &resource,
    const variadic_argument<object_view> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    shell_argument_array arguments{resource.value};
    if (arguments.empty()) {
        return {};
    }

    std::vector<shell_token> resource_tokens;
    for (const auto &param : params) {
        auto res = find_shi_from_params(
            arguments, resource_tokens, param.value, objects_excluded, limits, deadline);
        if (res.has_value()) {
            const std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            const bool ephemeral = resource.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match = condition_match{.args = {{.name = "resource"sv,
                                                       .resolved = std::move(arguments.resource),
                                                       .address = resource.address,
                                                       .key_path = resource_kp},
                                              {.name = "params"sv,
                                                  .resolved = highlight,
                                                  .address = param.address,
                                                  .key_path = param_kp}},
                .highlights = {std::move(highlight)},
                .operator_name = "shi_detector",
                .operator_value = {},
                .ephemeral = ephemeral};

            return {.outcome = true, .ephemeral = ephemeral};
        }
    }

    return {};
}

shi_detector::shi_detector(std::vector<condition_parameter> args)
    : base_impl<shi_detector>(std::move(args))
{}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
eval_result shi_detector::eval_impl(const unary_argument<object_view> &resource,
    const variadic_argument<object_view> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline) const
{
    if (resource.value.is<std::string_view>()) {
        return eval_string(resource, params, cache, objects_excluded, limits, deadline);
    }

    if (resource.value.type() == object_type::array) {
        return eval_array(resource, params, cache, objects_excluded, limits, deadline);
    }

    return {};
}
} // namespace ddwaf
