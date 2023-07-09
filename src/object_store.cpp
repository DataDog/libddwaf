// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <log.hpp>
#include <object_store.hpp>
#include <vector>

namespace ddwaf {
using object_and_attribute = std::pair<ddwaf_object *, object_store::attribute>;

object_store::object_store(ddwaf_object_free_fn free_fn) : obj_free_(free_fn)
{
    if (obj_free_ != nullptr) {
        objects_to_free_.reserve(default_num_objects);
    }
    ddwaf_object_map(&derivatives_);
}

object_store::~object_store()
{
    if (obj_free_ == nullptr) {
        return;
    }
    for (auto &obj : objects_to_free_) { obj_free_(&obj); }
}

bool object_store::insert(ddwaf_object &input, attribute attr)
{
    if (obj_free_ != nullptr) {
        objects_to_free_.emplace_back(input);
    }

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

        std::string key(array[i].parameterName, length);
        auto target = get_target_index(key);
        objects_[target] = {&array[i], attr};
        latest_batch_.emplace(target);
    }

    return true;
}


bool object_store::insert(const std::string &key, ddwaf_object &input, attribute attr)
{
    if ((attr | attribute::eval) != attribute::none) {
        if (obj_free_ != nullptr) {
            objects_to_free_.emplace_back(input);
        }

        auto target = get_target_index(key);
        objects_[target] = {input, attr};
        latest_batch_.emplace(target);
    }

    return true;
}

object_and_attribute object_store::get_target(target_index target) const
{
    auto it = objects_.find(target);
    return it != objects_.end() ? it->second : object_and_attribute{nullptr, attribute::none};
}

} // namespace ddwaf
