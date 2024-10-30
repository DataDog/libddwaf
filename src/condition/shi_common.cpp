// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "shi_common.hpp"

using namespace std::literals;

namespace ddwaf {

shell_argument_array::shell_argument_array(const ddwaf_object &root)
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
        if (child.type == DDWAF_OBJ_STRING && child.stringValue != nullptr && child.nbEntries > 0) {
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

        const std::string_view str{child.stringValue, static_cast<std::size_t>(child.nbEntries)};

        indices.emplace_back(index, index + str.size() - 1);

        index += str.size() + 1;

        if (!resource.empty()) {
            resource.append(" "sv);
        }
        resource.append(str);
    }
}

std::size_t shell_argument_array::find(std::string_view str, std::size_t start)
{
    while ((start = resource.find(str, start)) != npos) {
        auto end = start + str.size() - 1;
        // Lower bound returns the first element where the condition is false,
        // which must be equivalent to cur < start_pair for the binary search to
        // work as expected. The condition will match the first iterator where
        // cur.second >= start.
        auto res = std::lower_bound(indices.begin(), indices.end(), std::pair{start, 0},
            [](const auto &cur, const auto &start_pair) { return cur.second < start_pair.first; });

        if (res != indices.end() && res->first <= start && res->second >= end) {
            return start;
        }
        // Otherwise, there's overlap and it's not a valid match.

        // Attempt the next match
        start += 1;
    }
    return npos;
}

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

template std::optional<shi_result> shi_impl<std::string_view>(const std::string_view &resource,
    std::vector<shell_token> &resource_tokens, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline);

template std::optional<shi_result> shi_impl<shell_argument_array>(
    const shell_argument_array &resource, std::vector<shell_token> &resource_tokens,
    const ddwaf_object &params, const exclusion::object_set_ref &objects_excluded,
    const object_limits &limits, ddwaf::timer &deadline);
} // namespace ddwaf
