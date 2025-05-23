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
#include "object_type.hpp"
#include "target_address.hpp"

namespace ddwaf {

bool object_store::insert(owned_object &&input, attribute attr)
{
    object_view view;
    if (attr == attribute::ephemeral) {
        view = ephemeral_objects_.emplace_back(std::move(input));
    } else {
        view = input_objects_.emplace_back(std::move(input));
    }

    return insert(view, attr);
}

bool object_store::insert(object_view input, attribute attr)
{
    if (input.type() != object_type::map) {
        return false;
    }

    const auto size = input.size();
    if (size == 0) {
        // Objects with no addresses are considered valid as they are harmless
        return true;
    }

    objects_.reserve(objects_.size() + size);

    latest_batch_.reserve(latest_batch_.size() + size);

    if (attr == attribute::ephemeral) {
        ephemeral_targets_.reserve(size);
    }

    for (std::size_t i = 0; i < input.size(); ++i) {
        auto [key_obj, value] = input.at(i);
        if (key_obj.empty()) {
            continue;
        }

        auto key = key_obj.as<std::string_view>();
        auto target = get_target_index(key);
        insert_target_helper(target, key, value, attr);
    }

    return true;
}

bool object_store::insert(
    target_index target, std::string_view key, owned_object &&input, attribute attr)
{
    object_view view;
    if (attr == attribute::ephemeral) {
        view = ephemeral_objects_.emplace_back(std::move(input));
    } else {
        view = input_objects_.emplace_back(std::move(input));
    }

    return insert_target_helper(target, key, view, attr);
}

bool object_store::insert_target_helper(
    target_index target, std::string_view key, object_view view, attribute attr)
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

    objects_[target] = {view, attr};
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
    ephemeral_objects_.clear();
}

} // namespace ddwaf
