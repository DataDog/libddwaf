// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <object_store.hpp>
#include <log.hpp>
#include <vector>

namespace ddwaf
{

void object_store::insert(const ddwaf_object &input)
{
    latest_batch_.clear();

    if (input.type != DDWAF_OBJ_MAP || input.nbEntries == 0) {
        return;
    }

    std::size_t entries = static_cast<std::size_t>(input.nbEntries);
    const ddwaf_object* array = input.array;
    objects_.reserve(objects_.size() + entries);

    latest_batch_.reserve(entries);

    for (std::size_t i = 0; i < entries; ++i)
    {
        auto length = static_cast<std::size_t>(array[i].parameterNameLength);
        std::string key(array[i].parameterName, length);
        auto target = manifest_.get_target(key);

        objects_[target] = &array[i];
        latest_batch_.emplace(target);
    }
}

const ddwaf_object* object_store::get_target(manifest::target_type target) const
{
    auto it = objects_.find(target.root());
    return it != objects_.end() ? it->second : nullptr;
}

}
