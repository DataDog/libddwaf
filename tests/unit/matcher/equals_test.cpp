// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/equals.hpp"

#include "common/gtest/utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestEqualsBool, Basic)
{
    ddwaf_object tmp;
    {
        matcher::equals<bool> matcher(false);

        EXPECT_TRUE(matcher.match(false).first);
        EXPECT_FALSE(matcher.match(true).first);

        EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_BOOL));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_FLOAT));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_SIGNED));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_UNSIGNED));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_STRING));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_MAP));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_ARRAY));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_NULL));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_INVALID));

        EXPECT_TRUE(matcher.match(*ddwaf_object_bool(&tmp, false)).first);
        EXPECT_FALSE(matcher.match(*ddwaf_object_bool(&tmp, true)).first);
    }

    {
        matcher::equals<bool> matcher(true);

        EXPECT_TRUE(matcher.match(true).first);
        EXPECT_FALSE(matcher.match(false).first);

        EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_BOOL));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_FLOAT));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_SIGNED));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_UNSIGNED));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_STRING));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_MAP));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_ARRAY));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_NULL));
        EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_INVALID));

        EXPECT_TRUE(matcher.match(*ddwaf_object_bool(&tmp, true)).first);
        EXPECT_FALSE(matcher.match(*ddwaf_object_bool(&tmp, false)).first);
    }
}

TEST(TestEqualsInt, Basic)
{
    matcher::equals<int64_t> matcher(5);

    EXPECT_TRUE(matcher.match(5).first);
    EXPECT_FALSE(matcher.match(1).first);
    EXPECT_FALSE(matcher.match(-1).first);

    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_SIGNED));
    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_UNSIGNED));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_FLOAT));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_STRING));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_MAP));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_ARRAY));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_NULL));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_INVALID));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_BOOL));

    ddwaf_object tmp;
    EXPECT_TRUE(matcher.match(*ddwaf_object_signed(&tmp, 5)).first);
    EXPECT_TRUE(matcher.match(*ddwaf_object_unsigned(&tmp, 5)).first);

    EXPECT_FALSE(matcher.match(*ddwaf_object_signed(&tmp, 6)).first);
    EXPECT_FALSE(matcher.match(*ddwaf_object_unsigned(&tmp, 6)).first);
}

TEST(TestEqualsUint, Basic)
{
    matcher::equals<uint64_t> matcher(2132132);

    EXPECT_TRUE(matcher.match(2132132).first);
    EXPECT_FALSE(matcher.match(1).first);

    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_SIGNED));
    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_UNSIGNED));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_FLOAT));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_STRING));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_MAP));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_ARRAY));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_NULL));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_INVALID));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_BOOL));

    ddwaf_object tmp;
    EXPECT_TRUE(matcher.match(*ddwaf_object_signed(&tmp, 2132132)).first);
    EXPECT_TRUE(matcher.match(*ddwaf_object_unsigned(&tmp, 2132132)).first);

    EXPECT_FALSE(matcher.match(*ddwaf_object_signed(&tmp, 6)).first);
    EXPECT_FALSE(matcher.match(*ddwaf_object_unsigned(&tmp, 6)).first);
}

TEST(TestEqualsDouble, Basic)
{
    matcher::equals<double> matcher(5.01, 0.1);

    EXPECT_TRUE(matcher.match(5.01).first);
    EXPECT_FALSE(matcher.match(5.12).first);
    EXPECT_FALSE(matcher.match(-5.1).first);

    EXPECT_TRUE(matcher.is_supported_type(DDWAF_OBJ_FLOAT));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_SIGNED));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_UNSIGNED));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_STRING));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_MAP));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_ARRAY));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_NULL));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_INVALID));
    EXPECT_FALSE(matcher.is_supported_type(DDWAF_OBJ_BOOL));

    ddwaf_object tmp;
    EXPECT_TRUE(matcher.match(*ddwaf_object_float(&tmp, 5.01)).first);
    EXPECT_FALSE(matcher.match(*ddwaf_object_float(&tmp, 5.5)).first);
}

TEST(TestEqualsString, Basic)
{
    matcher::equals<std::string> matcher("aaaa");

    EXPECT_TRUE(matcher.match("aaaa"sv).first);
    EXPECT_TRUE(matcher.match("aaaa"s).first);

    EXPECT_FALSE(matcher.match("aaa"sv).first);
    EXPECT_FALSE(matcher.match("aaa"s).first);

    EXPECT_FALSE(matcher.match("cccc"sv).first);
    EXPECT_FALSE(matcher.match("cccc"s).first);
}

TEST(TestEqualsString, InvalidMatchInput)
{
    matcher::equals<std::string> matcher("aaaa");

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"aaaa", 0}).first);
}

} // namespace
