// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <string_view>

namespace ddwaf
{

class ruleset_info
{
public:
    explicit ruleset_info(ddwaf_ruleset_info* info_) : info(info_)
    {
        if (info == nullptr)
        {
            return;
        }
        info->loaded = 0;
        info->failed = 0;
        ddwaf_object_map(&info->errors);
    }

    void add_failed()
    {
        if (info != nullptr)
        {
            info->failed++;
        }
    }
    void add_loaded()
    {
        if (info != nullptr)
        {
            info->loaded++;
        }
    }

    void insert_error(std::string_view rule_id, std::string_view error)
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

protected:
    std::map<std::string_view, ddwaf_object*> errors;
    ddwaf_ruleset_info* info;
};

}
