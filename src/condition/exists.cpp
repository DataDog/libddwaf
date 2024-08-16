// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/exists.hpp"
#include "utils.hpp"

namespace ddwaf {

namespace {

enum class search_outcome { found, not_found, unknown };

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

    const ddwaf_object *parent = root;
    auto it = key_path.begin();

    std::size_t size = parent->nbEntries;

    // The parser ensures that the key path is within the limits specified by
    // the user, hence we don't need to check for depth
    for (std::size_t i = 0; i < size;) {
        const auto &child = parent->array[i++];

        if (child.parameterName == nullptr) [[unlikely]] {
            continue;
        }
        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

        if (key == *it) {
            if (objects_excluded.contains(&child)) {
                // We found the next child but it has been excluded, so we
                // can't know for sure if the required key path exists
                return search_outcome::unknown;
            }

            if (++it == key_path.end()) {
                return search_outcome::found;
            }

            if (child.type != DDWAF_OBJ_MAP) {
                return search_outcome::not_found;
            }

            // Reset the loop and iterate child
            parent = &child;
            i = 0;
            size = std::min(static_cast<uint32_t>(child.nbEntries), limits.max_container_size);
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
