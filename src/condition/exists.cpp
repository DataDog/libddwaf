// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/exists.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "object.hpp"
#include "object_type.hpp"

namespace ddwaf {

namespace {

enum class search_outcome : uint8_t { found, not_found, unknown };

object_view get_key(object_view root, const std::variant<std::string, int64_t> &key)
{
    if (root.is_map() && std::holds_alternative<std::string>(key)) {
        return root.find(std::get<std::string>(key));
    }

    if (root.is_array() && std::holds_alternative<int64_t>(key)) {
        auto index = std::get<int64_t>(key);
        if (index >= 0 && root.size() > static_cast<uint64_t>(index)) {
            return root.at_value(index);
        }

        if (index < 0 && root.size() >= static_cast<uint64_t>(-index)) {
            return root.at_value(root.size() + index);
        }
    }

    return {};
}

search_outcome exists(object_view root,
    std::span<const std::variant<std::string, int64_t>> key_path,
    const object_set_ref &objects_excluded)
{
    if (key_path.empty()) {
        return search_outcome::found;
    }

    auto it = key_path.begin();

    // Since there's a key path, the object must be a map
    if (std::holds_alternative<std::string>(*it) && root.type() != object_type::map) {
        return search_outcome::not_found;
    }

    if (std::holds_alternative<int64_t>(*it) && root.type() != object_type::array) {
        return search_outcome::not_found;
    }

    while ((root = get_key(root, *it)).has_value()) {
        if (objects_excluded.contains(root)) {
            // We found the next root but it has been excluded, so we
            // can't know for sure if the required key path exists
            return search_outcome::unknown;
        }

        if (++it == key_path.end()) {
            return search_outcome::found;
        }

        if (std::holds_alternative<std::string>(*it) && root.type() != object_type::map) {
            return search_outcome::not_found;
        }

        if (std::holds_alternative<int64_t>(*it) && root.type() != object_type::array) {
            return search_outcome::not_found;
        }
    }

    return search_outcome::not_found;
}

} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
[[nodiscard]] bool exists_condition::eval_impl(const variadic_argument<object_view> &inputs,
    condition_cache &cache, const object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    for (const auto &input : inputs) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (exists(input.value, input.key_path, objects_excluded) == search_outcome::found) {

            const std::vector<std::variant<std::string_view, int64_t>> key_path;

            cache.match = {{.args = {{.name = "input",
                                .resolved = {},
                                .address = input.address,
                                .key_path = convert_key_path(input.key_path)}},
                .highlights = {},
                .operator_name = "exists",
                .operator_value = {}}};
            return true;
        }
    }
    return false;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
[[nodiscard]] bool negated_exists_condition::eval_impl(const unary_argument<object_view> &input,
    condition_cache &cache, const object_set_ref &objects_excluded,
    ddwaf::timer & /*deadline*/) const
{
    // We need to make sure the key path hasn't been found. If the result is
    // unknown, we can't guarantee that the key path isn't actually present in
    // the data set
    if (exists(input.value, input.key_path, objects_excluded) != search_outcome::not_found) {
        return false;
    }

    cache.match = {{.args = {{.name = "input",
                        .resolved = {},
                        .address = input.address,
                        .key_path = convert_key_path(input.key_path)}},
        .highlights = {},
        .operator_name = "!exists",
        .operator_value = {}}};
    return true;
}

} // namespace ddwaf
