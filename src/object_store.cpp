// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <string_view>
#include <utility>

#include "log.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "target_address.hpp"
#include "utils.hpp"

namespace ddwaf {

bool object_store::insert(owned_object &&input, evaluation_scope scope)
{
    object_view view;
    if (scope == evaluation_scope::subcontext) {
        view = subcontext_objects_.emplace_back(std::move(input));
    } else {
        view = input_objects_.emplace_back(std::move(input));
    }

    if (!view.is_map()) {
        return false;
    }

    return insert(view, scope);
}

bool object_store::insert(map_view input, evaluation_scope scope)
{
    const auto size = input.size();
    if (size == 0) {
        // Objects with no addresses are considered valid as they are harmless
        return true;
    }

    objects_.reserve(objects_.size() + size);

    latest_batch_.reserve(latest_batch_.size() + size);

    if (scope == evaluation_scope::subcontext) {
        subcontext_targets_.reserve(size);
    }

    for (std::size_t i = 0; i < size; ++i) {
        auto [key_obj, value] = input.at(i);
        if (key_obj.empty()) {
            continue;
        }

        auto key = key_obj.as<std::string_view>();
        auto target = get_target_index(key);
        insert_target_helper(target, key, value, scope);
    }

    return true;
}

bool object_store::insert(
    target_index target, std::string_view key, owned_object &&input, evaluation_scope scope)
{
    object_view view;
    if (scope == evaluation_scope::subcontext) {
        view = subcontext_objects_.emplace_back(std::move(input));
    } else {
        view = input_objects_.emplace_back(std::move(input));
    }

    return insert_target_helper(target, key, view, scope);
}

bool object_store::insert_target_helper(
    target_index target, std::string_view key, object_view view, evaluation_scope scope)
{
    if (objects_.contains(target)) {
        if (scope == evaluation_scope::subcontext && !subcontext_targets_.contains(target)) {
            DDWAF_WARN("Failed to replace non-subcontext target '{}' with a subcontext one", key);
            return false;
        }

        if (scope == evaluation_scope::context && subcontext_targets_.contains(target)) {
            DDWAF_WARN("Failed to replace subcontext target '{}' with a non-subcontext one", key);
            return false;
        }

        DDWAF_DEBUG("Replacing {} target '{}' in object store",
            scope == evaluation_scope::subcontext ? "subcontext" : "context", key);
    } else {
        DDWAF_DEBUG("Inserting {} target '{}' into object store",
            scope == evaluation_scope::subcontext ? "subcontext" : "context", key);
    }

    if (scope == evaluation_scope::subcontext) {
        subcontext_targets_.emplace(target);
    }

    objects_[target] = {view, scope};
    latest_batch_.emplace(target);

    return true;
}

} // namespace ddwaf
