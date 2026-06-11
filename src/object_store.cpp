// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
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
    targets_.reserve(targets_.size() + size);
    if (mark_new) {
        latest_batch_.reserve(latest_batch_.size() + size);
    }

    for (std::size_t i = 0; i < size; ++i) {
        auto [key_obj, value] = batch.at(i);
        if (key_obj.empty()) {
            continue;
        }

        auto key = key_obj.as<std::string_view>();
        register_target(get_target_index(key), key, value, mark_new);
    }
}

void object_store::register_target(
    target_index target, std::string_view key, object_view value, bool mark_new)
{
    if (targets_.contains(target)) {
        DDWAF_DEBUG("Replacing target '{}' in object store", key);
    } else {
        DDWAF_DEBUG("Inserting target '{}' into object store", key);
    }

    targets_[target] = value;
    if (mark_new) {
        latest_batch_.emplace(target);
    }
}

} // namespace ddwaf
