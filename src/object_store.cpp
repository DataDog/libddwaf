// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
#include <log.hpp>
#include <object_store.hpp>
#include <vector>

namespace ddwaf {

using object_and_attribute = std::pair<ddwaf_object *, object_store::attribute>;

object_store::~object_store()
{
    for (auto [obj, free_fn] : input_objects_) {
        if (free_fn != nullptr) {
            free_fn(&obj);
        }
    }
}

bool object_store::insert(ddwaf_object &input, ddwaf_object_free_fn free_fn, attribute attr)
{
    input_objects_.emplace_back(input, free_fn);

    latest_batch_.clear();

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

    latest_batch_.reserve(entries);

    for (std::size_t i = 0; i < entries; ++i) {
        auto length = static_cast<std::size_t>(array[i].parameterNameLength);
        if (array[i].parameterName == nullptr || length == 0) {
            continue;
        }

        const std::string key(array[i].parameterName, length);
        auto target = get_target_index(key);
        objects_[target] = {&array[i], attr};
        latest_batch_.emplace(target);
    }

    return true;
}

bool object_store::insert(
    target_index target, ddwaf_object &input, ddwaf_object_free_fn free_fn, attribute attr)
{
    input_objects_.emplace_back(input, free_fn);

    auto *object = &input_objects_.back().first;
    objects_[target] = {object, attr};
    latest_batch_.emplace(target);

    return true;
}

object_and_attribute object_store::get_target(target_index target) const
{
    auto it = objects_.find(target);
    return it != objects_.end() ? it->second : object_and_attribute{nullptr, attribute::none};
}

} // namespace ddwaf
