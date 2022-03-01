// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"

extern "C"
{

    void ddwaf_ruleset_info_free(ddwaf_ruleset_info* info)
    {
        ddwaf_object_free(&info->errors);
    }
}
