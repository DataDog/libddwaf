// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/exists.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "object_type.hpp"
#include "object_view.hpp"
#include "utils.hpp"

namespace ddwaf {

namespace {

enum class search_outcome : uint8_t { found, not_found, unknown };

object_view find_key(const object_view &parent, std::string_view key, const object_limits &limits)
{
    for (auto it = parent.begin(limits); it; ++it) {
        const auto &child_key = it.key();

        if (key == child_key) {
            return it.value();
        }
    }

    return nullptr;
}

search_outcome exists(object_view root, std::span<const std::string> key_path,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits)
{
    if (key_path.empty()) {
        return search_outcome::found;
    }

    // Since there's a key path, the object must be a map
    if (root.type() != object_type::map) {
        return search_outcome::not_found;
    }

    auto it = key_path.begin();

    // The parser ensures that the key path is within the limits specified by
    // the user, hence we don't need to check for depth
    while ((root = find_key(root, *it, limits)).has_value()) {
        if (objects_excluded.contains(root.ptr())) {
            // We found the root root but it has been excluded, so we
            // can't know for sure if the required key path exists
            return search_outcome::unknown;
        }

        if (++it == key_path.end()) {
            return search_outcome::found;
        }

        if (root.type() != object_type::map) {
            return search_outcome::not_found;
        }
    }

    return search_outcome::not_found;
}

} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
[[nodiscard]] eval_result exists_condition::eval_impl(const variadic_argument<object_view> &inputs,
    condition_cache &cache, const exclusion::object_set_ref &objects_excluded,
    const object_limits &limits, ddwaf::timer &deadline) const
{
    for (const auto &input : inputs) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (exists(input.value, input.key_path, objects_excluded, limits) ==
            search_outcome::found) {
            std::vector<std::string> key_path{input.key_path.begin(), input.key_path.end()};
            cache.match = {{.args = {{.name = "input",
                                .resolved = {},
                                .address = input.address,
                                .key_path = std::move(key_path)}},
                .highlights = {},
                .operator_name = "exists",
                .operator_value = {},
                .ephemeral = input.ephemeral}};
            return {.outcome = true, .ephemeral = input.ephemeral};
        }
    }
    return {.outcome = false, .ephemeral = false};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
[[nodiscard]] eval_result exists_negated_condition::eval_impl(
    const unary_argument<object_view> &input, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer & /*deadline*/) const
{
    // We need to make sure the key path hasn't been found. If the result is
    // unknown, we can't guarantee that the key path isn't actually present in
    // the data set
    if (exists(input.value, input.key_path, objects_excluded, limits) !=
        search_outcome::not_found) {
        return {.outcome = false, .ephemeral = false};
    }

    std::vector<std::string> key_path{input.key_path.begin(), input.key_path.end()};
    cache.match = {{.args = {{.name = "input",
                        .resolved = {},
                        .address = input.address,
                        .key_path = std::move(key_path)}},
        .highlights = {},
        .operator_name = "!exists",
        .operator_value = {},
        .ephemeral = input.ephemeral}};
    return {.outcome = true, .ephemeral = input.ephemeral};
}

} // namespace ddwaf
