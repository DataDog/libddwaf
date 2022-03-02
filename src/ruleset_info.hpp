// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstring>
#include <ddwaf.h>
#include <map>
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
        info->loaded  = 0;
        info->failed  = 0;
        info->version = nullptr;
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

    void set_version(std::string_view version)
    {
        if (info == nullptr || version.size() == 0 || version == "")
        {
            return;
        }

        char* str = new char[version.size() + 1];
        std::memcpy(str, version.data(), version.size());
        str[version.size()] = '\0';
        info->version       = str;
    }

    void insert_error(std::string_view rule_id, std::string_view error);

protected:
    std::map<std::string_view, ddwaf_object*> errors;
    ddwaf_ruleset_info* info;
};

}
