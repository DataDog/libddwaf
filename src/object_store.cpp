// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "object_store.hpp"
#include "ddwaf.h"
#include "log.hpp"
#include "utils.hpp"
#include <cstddef>
#include <string>
#include <string_view>

namespace ddwaf {

bool object_store::insert(ddwaf_object &input, attribute attr, ddwaf_object_free_fn free_fn)
{
    if (attr == attribute::ephemeral) {
        ephemeral_objects_.emplace_back(input, free_fn);
    } else {
        input_objects_.emplace_back(input, free_fn);
    }

    if (input.type != DDWAF_OBJ_MAP) {
        return false;
    }

    auto entries = static_cast<std::size_t>(input.nbEntries);
    if (entries == 0) {
        // Objects with no addresses are considered valid as they are harmless
        return true;
    }

    ddwaf_object *array = input.array;
    if (array == nullptr) {
        // Since we have established that the size of the map is not 0, a null
        // array constitutes a malformed map.
        return false;
    }

    objects_.reserve(objects_.size() + entries);

    latest_batch_.reserve(latest_batch_.size() + entries);

    if (attr == attribute::ephemeral) {
        ephemeral_targets_.reserve(entries);
    }

    for (std::size_t i = 0; i < entries; ++i) {
        auto length = static_cast<std::size_t>(array[i].parameterNameLength);
        if (array[i].parameterName == nullptr || length == 0) {
            continue;
        }

        const std::string key(array[i].parameterName, length);
        auto target = get_target_index(key);

        insert_target_helper(target, key, &array[i], attr);
    }

    return true;
}

bool object_store::insert(target_index target, std::string_view key, ddwaf_object &input,
    attribute attr, ddwaf_object_free_fn free_fn)
{
    ddwaf_object *object = nullptr;
    if (attr == attribute::ephemeral) {
        ephemeral_objects_.emplace_back(input, free_fn);
        object = &ephemeral_objects_.back().first;
    } else {
        input_objects_.emplace_back(input, free_fn);
        object = &input_objects_.back().first;
    }

    return insert_target_helper(target, key, object, attr);
}

bool object_store::insert_target_helper(
    target_index target, std::string_view key, ddwaf_object *object, attribute attr)
{
    if (objects_.contains(target)) {
        if (attr == attribute::ephemeral && !ephemeral_targets_.contains(target)) {
            DDWAF_WARN("Failed to replace non-ephemeral target '{}' with an ephemeral one", key);
            return false;
        }

        if (attr == attribute::none && ephemeral_targets_.contains(target)) {
            DDWAF_WARN("Failed to replace ephemeral target '{}' with a non-ephemeral one", key);
            return false;
        }

        DDWAF_DEBUG("Replacing {} target '{}' in object store",
            attr == attribute::ephemeral ? "ephemeral" : "persistent", key);
    } else {
        DDWAF_DEBUG("Inserting {} target '{}' into object store",
            attr == attribute::ephemeral ? "ephemeral" : "persistent", key);
    }

    if (attr == attribute::ephemeral) {
        ephemeral_targets_.emplace(target);
    }

    objects_[target] = {object, attr};
    latest_batch_.emplace(target);

    return true;
}

void object_store::clear_last_batch()
{
    // Clear latest batch
    latest_batch_.clear();

    // Clear any ephemeral targets
    for (auto target : ephemeral_targets_) {
        auto it = objects_.find(target);
        if (it != objects_.end()) {
            objects_.erase(it);
        }
    }
    ephemeral_targets_.clear();

    // Free ephemeral objects and targets
    for (auto &[obj, free_fn] : ephemeral_objects_) {
        if (free_fn != nullptr) {
            free_fn(&obj);
        }
    }
    ephemeral_objects_.clear();
}

} // namespace ddwaf
