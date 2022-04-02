// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <utils.h>

namespace ddwaf
{

struct object_limits {
    uint32_t max_map_depth { DDWAF_MAX_MAP_DEPTH };
    uint32_t max_array_size { DDWAF_MAX_ARRAY_SIZE };
    uint32_t max_string_length { DDWAF_MAX_STRING_LENGTH };
};

class validator
{
public:
    validator() = default;
    validator(const object_limits &limits);

    bool validate(ddwaf_object input) const;

#ifdef TESTING
    FRIEND_TEST(TestValidator, TestMalformedUnsignedInt);
    FRIEND_TEST(TestValidator, TestMalformedSignedInt);
    FRIEND_TEST(TestValidator, TestMalformedString);
    FRIEND_TEST(TestValidator, TestMalformedMap);
    FRIEND_TEST(TestValidator, TestRecursiveMap);
    FRIEND_TEST(TestValidator, TestMalformedArray);
    FRIEND_TEST(TestValidator, TestRecursiveArray);
    FRIEND_TEST(TestValidator, TestInvalidType);
#endif

protected:
    bool validate_helper(ddwaf_object input, uint64_t depth = 0) const;

    object_limits limits_;
};

}
