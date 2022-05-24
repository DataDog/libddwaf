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

void object_store::insert_object(const ddwaf_object &input)
{
    latest_batch_.clear();

    if (input.nbEntries == 0) {
        return;
    }

    std::size_t entries = static_cast<std::size_t>(input.nbEntries);
    const ddwaf_object* array = input.array;
    objects_.reserve(objects_.size() + entries);

    std::unordered_set<std::string> keys;
    keys.reserve(entries);

    for (std::size_t i = 0; i < entries; ++i)
    {
        auto length = static_cast<std::size_t>(array[i].parameterNameLength);
        std::string key(array[i].parameterName, length);

        objects_[key] = &array[i];
        keys.emplace(std::move(key));
    }

    manifest_.findImpactedArgs(keys, latest_batch_);
}

const ddwaf_object* object_store::get_object(const PWManifest::ARG_ID target) const
{
    const auto& details = manifest_.getDetailsForTarget(target);

    auto param = objects_.find(details.inheritFrom);
    if (param == objects_.end())
    {
        return nullptr;
    }

    return param->second;
}

}
