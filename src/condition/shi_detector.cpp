// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/shi_detector.hpp"
#include "condition/match_iterator.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "tokenizer/shell.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

struct shi_result {
    std::string value;
    std::vector<std::string> key_path;
};

struct shell_argument_array {
    static constexpr std::size_t npos = std::string_view::npos;

    explicit shell_argument_array(std::size_t argc) { indices.reserve(argc); }

    void append(std::string_view arg)
    {
        indices.emplace_back(index, index + arg.size() - 1);

        index += arg.size() + 1;

        if (!resource.empty()) {
            resource.reserve(resource.size() + arg.size() + 1);
            resource.append(" "sv);
        } else {
            resource.reserve(arg.size());
        }
        resource.append(arg);
    }

    std::size_t find(std::string_view str, std::size_t start = 0)
    {
        while ((start = resource.find(str, start)) != npos) {
            auto end = start + str.size() - 1;

            // Ensure that both start and end are within the same argument
            std::size_t low = 0;
            std::size_t high = indices.size() - 1;
            while (high >= low) {
                auto mid = low + (high - low) / 2;
                auto [arg_start, arg_end] = indices[mid];

                // If the end of the current argument is after the start,
                // search the remaining arguments to the right of this one
                if (arg_end < start) {
                    low = mid + 1;
                    continue;
                }

                // If the start of the current argument is before the end,
                // search the remaining arguments to the left of this one.
                if (arg_start > end) {
                    high = mid - 1;
                    continue;
                }

                // If the start and end are within the boundaries of this
                // argument, we have determined that there is no overlap
                if (arg_start <= start && arg_end >= end) {
                    return start;
                }

                // Otherwise, there's overlap and it's not a valid match.
                break;
            }

            // Attempt the next match
            start += 1;
        }
        return npos;
    }

    std::vector<std::pair<std::size_t, std::size_t>> indices;
    std::string resource;
    std::size_t index{};
};

template <typename ResourceType>
std::optional<shi_result> shi_impl(const ResourceType &resource,
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
            if constexpr (std::is_same_v<ResourceType, shell_argument_array>) {
                shell_tokenizer tokenizer(resource.resource);
                resource_tokens = tokenizer.tokenize();
            } else {
                shell_tokenizer tokenizer(resource);
                resource_tokens = tokenizer.tokenize();
            }
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

eval_result shi_detector::eval_string(const unary_argument<const ddwaf_object *> &resource,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    if (resource.value->nbEntries == 0 || resource.value->stringValue == nullptr) {
        return {};
    }

    std::string_view resource_sv;
    resource_sv = {
        resource.value->stringValue, static_cast<std::size_t>(resource.value->nbEntries)};

    std::vector<shell_token> resource_tokens;
    for (const auto &param : params) {
        auto res = shi_impl(
            resource_sv, resource_tokens, *param.value, objects_excluded, limits_, deadline);
        if (res.has_value()) {
            std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            bool ephemeral = resource.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match = condition_match{
                {{"resource"sv, std::string{resource_sv}, resource.address, resource_kp},
                    {"params"sv, highlight, param.address, param_kp}},
                {std::move(highlight)}, "shi_detector", {}, ephemeral};

            return {true, ephemeral};
        }
    }

    return {};
}

eval_result shi_detector::eval_array(const unary_argument<const ddwaf_object *> &resource,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    shell_argument_array arguments{static_cast<std::size_t>(resource.value->nbEntries)};
    for (std::size_t i = 0; i < resource.value->nbEntries; ++i) {
        const auto &child = resource.value->array[i];
        std::string_view str;
        if (child.type == DDWAF_OBJ_STRING) {
            str = std::string_view{child.stringValue, static_cast<std::size_t>(child.nbEntries)};
        }
        arguments.append(str);
    }

    std::vector<shell_token> resource_tokens;
    for (const auto &param : params) {
        auto res =
            shi_impl(arguments, resource_tokens, *param.value, objects_excluded, limits_, deadline);
        if (res.has_value()) {
            std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            bool ephemeral = resource.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match = condition_match{
                {{"resource"sv, std::move(arguments.resource), resource.address, resource_kp},
                    {"params"sv, highlight, param.address, param_kp}},
                {std::move(highlight)}, "shi_detector", {}, ephemeral};

            return {true, ephemeral};
        }
    }

    return {};
}

shi_detector::shi_detector(std::vector<condition_parameter> args, const object_limits &limits)
    : base_impl<shi_detector>(std::move(args), limits)
{}

eval_result shi_detector::eval_impl(const unary_argument<const ddwaf_object *> &resource,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    if (resource.value->type == DDWAF_OBJ_STRING) {
        return eval_string(resource, params, cache, objects_excluded, deadline);
    }

    if (resource.value->type == DDWAF_OBJ_ARRAY) {
        return eval_array(resource, params, cache, objects_excluded, deadline);
    }

    return {};
}
} // namespace ddwaf
