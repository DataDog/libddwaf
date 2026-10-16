// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <algorithm>
#include <cstddef>
#include <string_view>

#include "log.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "target_address.hpp"

namespace ddwaf {

void object_store::apply(map_view batch, bool mark_new)
{
    const auto size = batch.size();
    for (std::size_t i = 0; i < size; ++i) {
        auto [key_obj, value] = batch.at(i);
        if (key_obj.empty()) {
            continue;
        }

        auto key = key_obj.as<std::string_view>();
        const auto target = lookup_ != nullptr ? lookup_->find(key) : get_target_index(key);
        if (target == target_lookup::npos) {
            DDWAF_DEBUG("Ignoring target '{}', not used by any component", key);
            continue;
        }

        register_target(target, key, value, mark_new);
    }
}

void object_store::register_target(
    target_index target, std::string_view key, object_view value, bool mark_new)
{
    if (target >= targets_.size()) {
        // The targets are allocated on first use, sized for every address in
        // the lookup. Afterwards, only targets registered after the lookup was
        // created (or any target, without a lookup) can be out of bounds.
        const std::size_t lookup_size = lookup_ != nullptr ? lookup_->size() : 0;
        reserve_targets(std::max({target + 1, targets_.size() * 2, lookup_size}));
    }

    auto &slot = targets_[target];
    if (slot.has_value()) {
        DDWAF_DEBUG("Replacing target '{}' in object store", key);
    } else {
        DDWAF_DEBUG("Inserting target '{}' into object store", key);
        ++target_count_;
    }

    slot = value;
    updated_targets_.insert(target);
    if (mark_new) {
        latest_batch_.insert(target);
    }
}

} // namespace ddwaf
