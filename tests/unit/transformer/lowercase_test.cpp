// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "transformer/lowercase.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;

namespace {
TEST(TestLowercase, NameAndID)
{
    EXPECT_STREQ(transformer::lowercase::name().data(), "lowercase");
    EXPECT_EQ(transformer::lowercase::id(), transformer_id::lowercase);
}

TEST(TestLowercase, EmptyString) { EXPECT_NO_TRANSFORM(lowercase, ""); }

TEST(TestLowercase, ValidTransform)
{
    EXPECT_TRANSFORM(lowercase, "L", "l");
    EXPECT_TRANSFORM(lowercase, "zzzzzzzzzzzzzzzZ", "zzzzzzzzzzzzzzzz");
    EXPECT_TRANSFORM(lowercase, "aaaaaaaaaaaaaaaA", "aaaaaaaaaaaaaaaa");
    EXPECT_TRANSFORM(lowercase, "LE", "le");
    EXPECT_TRANSFORM(lowercase, "LoWeRCase", "lowercase");
    EXPECT_TRANSFORM(lowercase, "LowercasE", "lowercase");
    EXPECT_TRANSFORM(lowercase, "lowercasE", "lowercase");
    EXPECT_TRANSFORM(lowercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz");
    EXPECT_TRANSFORM(
        lowercase, "lowercasEasndasnjdkans1823712nka", "lowercaseasndasnjdkans1823712nka");
}

TEST(TestLowercase, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(lowercase, "l");
    EXPECT_NO_TRANSFORM(lowercase, "le");
    EXPECT_NO_TRANSFORM(lowercase, "lowercase");
    EXPECT_NO_TRANSFORM(lowercase, "lowercase but it doesn't matter");
}

} // namespace
