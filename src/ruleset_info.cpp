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

    ddwaf_object *rules, id, tmp;

    auto it = errors.find(error);
    if (it == errors.end())
    {
        ddwaf_object_array(&tmp);
        bool res = ddwaf_object_map_addl(&info->errors,
                                         error.data(), error.size(), &tmp);
        if (!res)
        {
            return;
        }

        // Get the map element we just added
        rules = &info->errors.array[info->errors.nbEntries - 1];
        std::string_view key(rules->parameterName, rules->parameterNameLength);
        errors[key] = rules;
    }
    else
    {
        rules = it->second;
    }

    ddwaf_object_stringl(&id, rule_id.data(), rule_id.size());
    ddwaf_object_array_add(rules, &id);

    add_failed();
}

}
