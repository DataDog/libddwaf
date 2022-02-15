// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ddwaf.h>

namespace ddwaf
{

class validator
{
public:
    validator() = default;
    validator(uint64_t max_map_depth, uint64_t max_array_length);

    bool validate(ddwaf_object input) const;
    bool validate_helper(ddwaf_object input, uint64_t depth = 0) const;

protected:
    uint64_t max_map_depth_{DDWAF_MAX_MAP_DEPTH};
    uint64_t max_array_length_{DDWAF_MAX_ARRAY_LENGTH};
};

}
