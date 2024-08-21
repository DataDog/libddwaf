// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/match_iterator.hpp"
#include "condition/shi_detector.hpp"
#include "condition/structured_condition.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "tokenizer/shell.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

struct shi_result {
    std::string value;
    std::vector<std::string> key_path;
};

std::optional<shi_result> shi_string_impl(std::string_view resource,
    std::vector<shell_token> &resource_tokens, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    match_iterator it(resource, &params, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto [param, param_index] = *it;

        if (resource_tokens.empty()) {
            shell_tokenizer tokenizer(resource);
            resource_tokens = tokenizer.tokenize();
        }

        auto end_index = param_index + param.size();

        // Find first token
        std::size_t i = 0;
        for (; i < resource_tokens.size(); ++i) {
            const auto &token = resource_tokens[i];
            if (end_index >= token.index && param_index < (token.index + token.str.size())) {
                break;
            }
        }

        // Ignore if it's a single token
        if ((i + 1) < resource_tokens.size() && resource_tokens[i + 1].index >= end_index) {
            continue;
        }

        for (; i < resource_tokens.size(); ++i) {
            const auto &token = resource_tokens[i];
            if (token.type == shell_token_type::executable ||
                token.type == shell_token_type::redirection) {
                return {{std::string(param), it.get_current_path()}};
            }
        }
    }

    return std::nullopt;
}

} // namespace

shi_detector::shi_detector(std::vector<condition_parameter> args, const object_limits &limits)
    : base_impl<shi_detector>(std::move(args), limits)
{}

eval_result shi_detector::eval_impl(const unary_argument<std::string_view> &resource,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    std::vector<shell_token> resource_tokens;

    for (const auto &param : params) {
        auto res = shi_string_impl(
            resource.value, resource_tokens, *param.value, objects_excluded, limits_, deadline);
        if (res.has_value()) {
            std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            const bool ephemeral = resource.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match = condition_match{
                {{"resource"sv, std::string{resource.value}, resource.address, resource_kp},
                    {"params"sv, highlight, param.address, param_kp}},
                {std::move(highlight)}, "shi_detector", {}, ephemeral};

            return {true, ephemeral};
        }
    }

    return {};
}
} // namespace ddwaf
