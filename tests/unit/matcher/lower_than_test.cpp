// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/lower_than.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestlowerThanInt, Basic)
{
    matcher::lower_than<int64_t> matcher(5);

    EXPECT_TRUE(matcher.match(-1).first);
    EXPECT_TRUE(matcher.match(4).first);
    EXPECT_FALSE(matcher.match(6).first);
    EXPECT_FALSE(matcher.match(5).first);
    EXPECT_FALSE(matcher.match(99).first);

    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_FLOAT));
    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_SIGNED));
    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_UNSIGNED));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_STRING));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_MAP));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_ARRAY));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_NULL));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_INVALID));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_BOOL));

    ddwaf_object tmp;
    EXPECT_TRUE(matcher.match(*ddwaf_object_signed(&tmp, 4)).first);
    EXPECT_TRUE(matcher.match(*ddwaf_object_unsigned(&tmp, 4)).first);
    EXPECT_TRUE(matcher.match(*ddwaf_object_float(&tmp, 4.0)).first);

    EXPECT_FALSE(matcher.match(*ddwaf_object_signed(&tmp, 5)).first);
    EXPECT_FALSE(matcher.match(*ddwaf_object_unsigned(&tmp, 5)).first);
    EXPECT_FALSE(matcher.match(*ddwaf_object_float(&tmp, 5.0)).first);
}

TEST(TestlowerThanUint, Basic)
{
    matcher::lower_than<uint64_t> matcher(2132132);

    EXPECT_TRUE(matcher.match(2132131).first);
    EXPECT_FALSE(matcher.match(2132133).first);
    EXPECT_FALSE(matcher.match(2132132).first);

    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_FLOAT));
    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_SIGNED));
    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_UNSIGNED));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_STRING));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_MAP));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_ARRAY));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_NULL));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_INVALID));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_BOOL));

    ddwaf_object tmp;
    EXPECT_TRUE(matcher.match(*ddwaf_object_signed(&tmp, 2132131)).first);
    EXPECT_TRUE(matcher.match(*ddwaf_object_unsigned(&tmp, 2132131)).first);
    EXPECT_TRUE(matcher.match(*ddwaf_object_float(&tmp, 2132131.9)).first);

    EXPECT_FALSE(matcher.match(*ddwaf_object_signed(&tmp, 2132133)).first);
    EXPECT_FALSE(matcher.match(*ddwaf_object_unsigned(&tmp, 2132133)).first);
    EXPECT_FALSE(matcher.match(*ddwaf_object_float(&tmp, 2132132.1)).first);
}

TEST(TestlowerThanDouble, Basic)
{
    matcher::lower_than<double> matcher(5.1);

    EXPECT_TRUE(matcher.match(5.09).first);
    EXPECT_TRUE(matcher.match(-5.1).first);
    EXPECT_FALSE(matcher.match(5.1).first);
    EXPECT_FALSE(matcher.match(5.2).first);

    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_FLOAT));
    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_SIGNED));
    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_UNSIGNED));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_STRING));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_MAP));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_ARRAY));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_NULL));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_INVALID));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_BOOL));

    ddwaf_object tmp;
    EXPECT_TRUE(matcher.match(*ddwaf_object_signed(&tmp, 5)).first);
    EXPECT_TRUE(matcher.match(*ddwaf_object_unsigned(&tmp, 5)).first);
    EXPECT_TRUE(matcher.match(*ddwaf_object_float(&tmp, 5.09)).first);

    EXPECT_FALSE(matcher.match(*ddwaf_object_signed(&tmp, 6)).first);
    EXPECT_FALSE(matcher.match(*ddwaf_object_unsigned(&tmp, 6)).first);
    EXPECT_FALSE(matcher.match(*ddwaf_object_float(&tmp, 6.0)).first);
}

} // namespace
