// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "clock.hpp"
#include "condition/match_iterator.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "object.hpp"
#include "tokenizer/shell.hpp"

namespace ddwaf {

struct shi_result {
    std::string value;
    std::vector<std::variant<std::string_view, int64_t>> key_path;
};

struct shell_argument_array {
    static constexpr std::size_t npos = std::string_view::npos;

    explicit shell_argument_array(object_view root);
    std::size_t find(std::string_view str, std::size_t start = 0);
    [[nodiscard]] bool empty() const { return resource.empty(); }

    std::vector<std::pair<std::size_t, std::size_t>> indices;
    std::string resource;
};

template <typename ResourceType, typename IteratorType = kv_iterator>
std::optional<shi_result> find_shi_from_params(const ResourceType &resource,
    std::vector<shell_token> &resource_tokens, object_view params,
    const object_set_ref &objects_excluded, ddwaf::timer &deadline)
{
    match_iterator<2, IteratorType, ResourceType> it(resource, params, objects_excluded);
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

        for (; i < resource_tokens.size() && end_index >= resource_tokens[i].index; ++i) {
            const auto &token = resource_tokens[i];
            if (token.type == shell_token_type::executable ||
                token.type == shell_token_type::redirection) {
                return {{std::string(param), it.get_current_path()}};
            }
        }
    }

    return std::nullopt;
}

} // namespace ddwaf
