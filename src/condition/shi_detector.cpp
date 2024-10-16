// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <algorithm>
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

struct shell_argument_array {
    static constexpr std::size_t npos = std::string_view::npos;

    explicit shell_argument_array(const ddwaf_object &root)
    {
        // Since the type check is performed elsewhere, we don't need to check again
        auto argc = static_cast<std::size_t>(root.nbEntries);
        if (argc == 0) {
            return;
        }

        // Calculate the final resource length
        std::size_t resource_len = 0;
        for (std::size_t i = 0; i < argc; ++i) {
            const auto &child = root.array[i];
            if (child.type == DDWAF_OBJ_STRING && child.stringValue != nullptr &&
                child.nbEntries > 0) {
                // if the string is valid or non-empty, increase the resource
                // length + 1 for the extra space when relevant
                resource_len +=
                    static_cast<std::size_t>(child.nbEntries) + static_cast<std::size_t>(i > 0);
            }
        }

        indices.reserve(argc);
        resource.reserve(resource_len);

        std::size_t index = 0;
        for (std::size_t i = 0; i < argc; ++i) {
            const auto &child = root.array[i];
            if (child.type != DDWAF_OBJ_STRING || child.stringValue == nullptr ||
                child.nbEntries == 0) {
                continue;
            }

            const std::string_view str{
                child.stringValue, static_cast<std::size_t>(child.nbEntries)};

            indices.emplace_back(index, index + str.size() - 1);

            index += str.size() + 1;

            if (!resource.empty()) {
                resource.append(" "sv);
            }
            resource.append(str);
        }
    }

    std::size_t find(std::string_view str, std::size_t start = 0)
    {
        while ((start = resource.find(str, start)) != npos) {
            auto end = start + str.size() - 1;
            // Lower bound returns the first element where the condition is false,
            // which must be equivalent to cur < start_pair for the binary search to
            // work as expected. The condition will match the first iterator where
            // cur.second >= start.
            auto res = std::lower_bound(indices.begin(), indices.end(), std::pair{start, 0},
                [](const auto &cur, const auto &start_pair) {
                    return cur.second < start_pair.first;
                });

            if (res != indices.end() && res->first <= start && res->second >= end) {
                return start;
            }
            // Otherwise, there's overlap and it's not a valid match.

            // Attempt the next match
            start += 1;
        }
        return npos;
    }

    [[nodiscard]] bool empty() const { return resource.empty(); }

    std::vector<std::pair<std::size_t, std::size_t>> indices;
    std::string resource;
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
            const bool ephemeral = resource.ephemeral || param.ephemeral;

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
    shell_argument_array arguments{*resource.value};
    if (arguments.empty()) {
        return {};
    }

    std::vector<shell_token> resource_tokens;
    for (const auto &param : params) {
        auto res =
            shi_impl(arguments, resource_tokens, *param.value, objects_excluded, limits_, deadline);
        if (res.has_value()) {
            std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            const bool ephemeral = resource.ephemeral || param.ephemeral;

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
