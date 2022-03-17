// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <ruleset_info.hpp>

extern "C"
{

    void ddwaf_ruleset_info_free(ddwaf_ruleset_info* info)
    {
        if (info != nullptr)
        {
            ddwaf_object_free(&info->errors);
            delete[] info->version;
        }
    }
}

namespace ddwaf
{

void ruleset_info::insert_error(std::string_view rule_id, std::string_view error)
{
    if (info == nullptr)
    {
        return;
    }

    ddwaf_object *rule_array, id_str;

    auto it = error_obj_cache.find(error);
    if (it == error_obj_cache.end())
    {
        ddwaf_object tmp_array;
        ddwaf_object_array(&tmp_array);
        bool res = ddwaf_object_map_addl(&info->errors,
                                         error.data(), error.size(), &tmp_array);
        if (!res)
        {
            return;
        }

        // Get the map element we just added
        uint64_t index = info->errors.nbEntries - 1;
        rule_array = &info->errors.array[index];
        std::string_view key(rule_array->parameterName,
                             rule_array->parameterNameLength);
        error_obj_cache[key] = index;
    }
    else
    {
        rule_array = &info->errors.array[it->second];
    }

    ddwaf_object_stringl(&id_str, rule_id.data(), rule_id.size());
    ddwaf_object_array_add(rule_array, &id_str);

    add_failed();
}

}
