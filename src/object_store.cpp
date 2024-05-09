// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "object_store.hpp"
#include "ddwaf.h"
#include "log.hpp"

namespace ddwaf {

bool object_store::insert(owned_object input, attribute attr)
{
    if (attr == attribute::ephemeral) {
        ephemeral_objects_.emplace_back(std::move(input));
    } else {
        input_objects_.emplace_back(std::move(input));
    }

    auto input_view = input_objects_.back().view();
    if (input_view.type() != object_type::map) {
        return false;
    }

    auto input_map = input_view.as<map_object_view>();

    auto entries = input_map.size();
    if (entries == 0) {
        // Objects with no addresses are considered valid as they are harmless
        return true;
    }

    objects_.reserve(objects_.size() + entries);

    latest_batch_.reserve(latest_batch_.size() + entries);

    if (attr == attribute::ephemeral) {
        ephemeral_targets_.reserve(entries);
    }

    for (auto [key, value] : input_map) {
        if (key.length() == 0) {
            continue;
        }

        auto target = get_target_index(key);
        insert_target_helper(target, key, value, attr);
    }

    return true;
}

bool object_store::insert(
    target_index target, std::string_view key, owned_object input, attribute attr)
{
    object_view input_view;
    if (attr == attribute::ephemeral) {
        ephemeral_objects_.emplace_back(std::move(input));
        input_view = ephemeral_objects_.back().view();
    } else {
        input_objects_.emplace_back(std::move(input));
        input_view = input_objects_.back().view();
    }

    return insert_target_helper(target, key, input_view, attr);
}

bool object_store::insert_target_helper(
    target_index target, std::string_view key, object_view value, attribute attr)
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

    objects_[target] = {value, attr};
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
    ephemeral_objects_.clear();
}

} // namespace ddwaf
