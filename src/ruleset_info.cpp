// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

#include "ddwaf.h"
#include "ruleset_info.hpp"

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

void ruleset_info::section_info::add_loaded(std::string_view id)
{
    ddwaf_object id_str;
    ddwaf_object_stringl(&id_str, id.data(), id.size());
    ddwaf_object_array_add(&loaded_, &id_str);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void ruleset_info::section_info::add_failed(std::string_view id, diagnostic_severity sev, std::string_view error)
{
    const auto &inserter = [&](auto &cache, auto &diagnostics_array) {
        ddwaf_object id_str;
        auto it = cache.find(error);
        if (it == cache.end()) {
            ddwaf_object tmp_array;
            ddwaf_object_array(&tmp_array);

            auto [index, array] = object_map_add_helper(&diagnostics_array, error, &tmp_array);

            const std::string_view key(array->parameterName, array->parameterNameLength);
            error_obj_cache_[key] = index;

            ddwaf_object_stringl(&id_str, id.data(), id.size());
            ddwaf_object_array_add(array, &id_str);

        } else {
            ddwaf_object_stringl(&id_str, id.data(), id.size());
            ddwaf_object_array_add(&diagnostics_array.array[it->second], &id_str);
        }

        ddwaf_object_stringl(&id_str, id.data(), id.size());
        ddwaf_object_array_add(&failed_, &id_str);
    };

    if (sev == diagnostic_severity::error) {
        inserter(error_obj_cache_, errors_);
    } else {
        inserter(warning_obj_cache_, warnings_);
    }
}

void ruleset_info::section_info::add_skipped(std::string_view id)
{
    ddwaf_object id_str;
    ddwaf_object_stringl(&id_str, id.data(), id.size());
    ddwaf_object_array_add(&skipped_, &id_str);
}

} // namespace ddwaf
