// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <ruleset_info.hpp>

namespace ddwaf {

namespace {
std::pair<uint64_t, ddwaf_object *> object_map_add_helper(
    ddwaf_object *map, std::string_view key, ddwaf_object *object)
{
    ddwaf_object_map_addl(map, key.data(), key.length(), object);
    // Get the element we just added
    const uint64_t index = map->nbEntries - 1;
    return {index, &map->array[index]};
}
} // namespace

void ruleset_info::section_info::insert(std::string_view id, std::string_view error)
{
    ddwaf_object *array;
    ddwaf_object id_str;
    if (!error.empty()) {
        auto it = error_obj_cache.find(error);
        if (it == error_obj_cache.end()) {
            ddwaf_object tmp_array;
            ddwaf_object_array(&tmp_array);

            auto [index, new_array] = object_map_add_helper(&errors, error, &tmp_array);
            array = new_array;

            const std::string_view key(array->parameterName, array->parameterNameLength);
            error_obj_cache[key] = index;
        } else {
            array = &errors.array[it->second];
        }
    } else {
        array = &loaded;
    }

    ddwaf_object_stringl(&id_str, id.data(), id.size());
    ddwaf_object_array_add(array, &id_str);
}

} // namespace ddwaf
