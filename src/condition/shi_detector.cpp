// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/shi_detector.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "tokenizer/shell.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

using shi_result = std::optional<std::pair<std::string, std::vector<std::string>>>;

shi_result shi_string_impl(std::string_view resource, std::vector<shell_token> &resource_tokens,
    const ddwaf_object &params, const exclusion::object_set_ref &objects_excluded,
    const object_limits &limits, ddwaf::timer &deadline)
{
    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &object = *(*it);
        if (object.type != DDWAF_OBJ_STRING) {
            continue;
        }

        std::string_view param{object.stringValue, static_cast<std::size_t>(object.nbEntries)};
        auto param_index = resource.find(param);
        if (param_index == std::string_view::npos) {
            // Seemingly no injection
            continue;
        }

        if (resource_tokens.empty()) {
            shell_tokenizer tokenizer(resource);
            resource_tokens = tokenizer.tokenize();
        }

        auto end_index = param_index + param.size();

        // Find first token
        std::size_t i = 0;
        for (; i < resource_tokens.size(); ++i) {
            const auto &token = resource_tokens[i];
            if (token.index >= param_index && token.index <= end_index) {
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
    shi_result res;
    std::vector<shell_token> resource_tokens;

    for (const auto &param : params) {
        auto res = shi_string_impl(
            resource.value, resource_tokens, *param.value, objects_excluded, limits_, deadline);
        if (res.has_value()) {
            std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            bool ephemeral = resource.ephemeral || param.ephemeral;

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
