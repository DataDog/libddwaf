// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <span>
#include <string_view>
#include <unordered_map>

#include "attribute_collector.hpp"
#include "object_store.hpp"
#include "target_address.hpp"
#include "utils.hpp"

namespace ddwaf {

// This method creates a copy of the provided object
bool attribute_collector::emplace(std::string_view key, const ddwaf_object &value, bool copy)
{
    if (emplaced_attributes_.contains(key)) {
        return false;
    }

    auto object = copy ? object::clone(&value) : value;
    auto res = ddwaf_object_map_addl(&attributes_, key.data(), key.size(), &object);
    if (res) {
        if (copy) {
            ddwaf_object_free(&object);
        }
    } else {
        emplaced_attributes_.emplace(key);
    }
    return res;
}

void attribute_collector::collect(const object_store &store, target_index input_target,
    std::span<std::string> input_key_path, std::string_view output)
{
    auto state = collect_helper(store, input_target, input_key_path, output);
    if (state == collection_state::unavailable) {
        pending_.emplace(output, target_type{input_target, input_key_path});
    }
}

void attribute_collector::collect_pending(const object_store &store)
{
    for (auto it = pending_.begin(); it != pending_.end(); ++it) {
        auto output = it->first;
        auto &[input_target, input_key_path] = it->second;

        auto state = collect_helper(store, input_target, input_key_path, output);
        if (state != collection_state::unavailable) {
            it = pending_.erase(it);
        }
    }
}

attribute_collector::collection_state attribute_collector::collect_helper(const object_store &store,
    target_index input_target, std::span<std::string> input_key_path, std::string_view output)
{
    auto [object, attr] = store.get_target(input_target);
    if (object == nullptr) {
        return collection_state::unavailable;
    }

    const auto *resolved = object::find_key_path(*object, input_key_path);
    if (resolved == nullptr) {
        // The key path is not expected to be provided later on, therefore
        // we mark it as failed.
        return collection_state::failed;
    }

    if (object::is_scalar(resolved)) {
        emplace(output, *resolved, true);
    } else if (resolved->type == DDWAF_OBJ_ARRAY && resolved->nbEntries > 0) {
        emplace(output, resolved->array[0], true);
    } else {
        // The type is not a valid one, we mark it as failed.
        return collection_state::failed;
    }

    return collection_state::success;
}

} // namespace ddwaf
