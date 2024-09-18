// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <algorithm>
#include <cstddef>
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
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "utils.hpp"

namespace ddwaf {

namespace {

enum class search_outcome { found, not_found, unknown };

const ddwaf_object *find_key(
    const ddwaf_object &parent, std::string_view key, const object_limits &limits)
{
    const std::size_t size =
        std::min(static_cast<uint32_t>(parent.nbEntries), limits.max_container_size);
    for (std::size_t i = 0; i < size; ++i) {
        const auto &child = parent.array[i];

        if (child.parameterName == nullptr) [[unlikely]] {
            continue;
        }
        const std::string_view child_key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

        if (key == child_key) {
            return &child;
        }
    }

    return nullptr;
}

search_outcome exists(const ddwaf_object *root, std::span<const std::string> key_path,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits)
{
    if (key_path.empty()) {
        return search_outcome::found;
    }

    // Since there's a key path, the object must be a map
    if (root->type != DDWAF_OBJ_MAP) {
        return search_outcome::not_found;
    }

    auto it = key_path.begin();

    // The parser ensures that the key path is within the limits specified by
    // the user, hence we don't need to check for depth
    while ((root = find_key(*root, *it, limits)) != nullptr) {
        if (objects_excluded.contains(root)) {
            // We found the next root but it has been excluded, so we
            // can't know for sure if the required key path exists
            return search_outcome::unknown;
        }

        if (++it == key_path.end()) {
            return search_outcome::found;
        }

        if (root->type != DDWAF_OBJ_MAP) {
            return search_outcome::not_found;
        }
    }

    return search_outcome::not_found;
}

} // namespace

[[nodiscard]] eval_result exists_condition::eval_impl(
    const variadic_argument<const ddwaf_object *> &inputs, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    for (const auto &input : inputs) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (exists(input.value, input.key_path, objects_excluded, limits_) ==
            search_outcome::found) {
            std::vector<std::string> key_path{input.key_path.begin(), input.key_path.end()};
            cache.match = {{{{"input", {}, input.address, std::move(key_path)}}, {}, "exists", {},
                input.ephemeral}};
            return {true, input.ephemeral};
        }
    }
    return {false, false};
}

[[nodiscard]] eval_result exists_negated_condition::eval_impl(
    const unary_argument<const ddwaf_object *> &input, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer & /*deadline*/) const
{
    // We need to make sure the key path hasn't been found. If the result is
    // unknown, we can't guarantee that the key path isn't actually present in
    // the data set
    if (exists(input.value, input.key_path, objects_excluded, limits_) !=
        search_outcome::not_found) {
        return {false, false};
    }

    std::vector<std::string> key_path{input.key_path.begin(), input.key_path.end()};
    cache.match = {
        {{{"input", {}, input.address, std::move(key_path)}}, {}, "!exists", {}, input.ephemeral}};
    return {true, input.ephemeral};
}

} // namespace ddwaf
