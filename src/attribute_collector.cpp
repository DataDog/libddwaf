// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include "attribute_collector.hpp"
#include "ddwaf.h"
#include "log.hpp"
#include "object_helpers.hpp"
#include "object_store.hpp"
#include "target_address.hpp"

namespace ddwaf {

bool attribute_collector::insert(std::string_view key, const ddwaf_object &value, bool copy)
{
    if (inserted_or_pending_attributes_.contains(key)) {
        return false;
    }

    return insert_helper(key, value, copy);
}

bool attribute_collector::collect(const object_store &store, target_index input_target,
    std::span<const std::string> input_key_path, std::string_view attribute_key)
{
    if (inserted_or_pending_attributes_.contains(attribute_key)) {
        DDWAF_DEBUG("Not collecting duplicate attribute: {}", attribute_key);
        return false;
    }

    auto state = collect_helper(store, input_target, input_key_path, attribute_key);
    if (state == collection_state::unavailable) {
        pending_.emplace(attribute_key, target_type{input_target, input_key_path});
        DDWAF_DEBUG("Attribute added to pending queue: {}", attribute_key);
    }

    return state != collection_state::failed;
}

void attribute_collector::collect_pending(const object_store &store)
{
    for (auto it = pending_.begin(); it != pending_.end();) {
        auto attribute_key = it->first;
        // No need to check if the key is already present, as emplace and collect
        // already perform the check. As for items in the pending map, since the
        // map key is the attribute key, duplicates aren't possible.
        auto &[input_target, input_key_path] = it->second;

        auto state = collect_helper(store, input_target, input_key_path, attribute_key);
        if (state != collection_state::unavailable) {
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
}

attribute_collector::collection_state attribute_collector::collect_helper(const object_store &store,
    target_index input_target, std::span<const std::string> input_key_path,
    std::string_view attribute_key)
{
    auto [object, attr] = store.get_target(input_target);
    if (object == nullptr) {
        return collection_state::unavailable;
    }

    const auto *resolved = object::find_key_path(object, input_key_path, {}, {});
    if (resolved == nullptr) {
        // The key path is not expected to be provided later on, therefore
        // we mark it as failed.
        return collection_state::failed;
    }

    if (object::is_scalar(resolved)) {
        insert_helper(attribute_key, *resolved, true);
        return collection_state::success;
    }

    if (resolved->type == DDWAF_OBJ_ARRAY && resolved->nbEntries > 0) {
        auto &candidate = resolved->array[0];
        if (object::is_scalar(&candidate)) {
            insert_helper(attribute_key, candidate, true);
            return collection_state::success;
        }
    }
    return collection_state::failed;
}

bool attribute_collector::insert_helper(std::string_view key, const ddwaf_object &value, bool copy)
{
    auto object = copy ? object::clone(&value) : value;
    auto res = ddwaf_object_map_addl(&attributes_, key.data(), key.size(), &object);
    if (!res) {
        if (copy) {
            ddwaf_object_free(&object);
        }
    } else {
        DDWAF_DEBUG("Collected attribute: {}", key);
        inserted_or_pending_attributes_.insert(key);
    }
    return res;
}

} // namespace ddwaf
