// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/lowercase.hpp"

TEST(TestLowercase, NameAndID)
{
    EXPECT_STREQ(transformer::lowercase::name().data(), "lowercase");
    EXPECT_EQ(transformer::lowercase::id(), transformer_id::lowercase);
}

TEST(TestLowercase, EmptyString)
{
    lazy_string str("");
    EXPECT_FALSE(transformer::lowercase::transform(str));
    EXPECT_FALSE(str.modified());
}

TEST(TestLowercase, ValidTransform)
{
    {
        lazy_string str("L");
        EXPECT_TRUE(transformer::lowercase::transform(str));
        EXPECT_STREQ(str.data(), "l");
    }

    {
        lazy_string str("LE");
        EXPECT_TRUE(transformer::lowercase::transform(str));
        EXPECT_STREQ(str.data(), "le");
    }

    {
        lazy_string str("LoWeRCase");
        EXPECT_TRUE(transformer::lowercase::transform(str));
        EXPECT_STREQ(str.data(), "lowercase");
    }

    {
        lazy_string str("LowercasE");
        EXPECT_TRUE(transformer::lowercase::transform(str));
        EXPECT_STREQ(str.data(), "lowercase");
    }

    {
        lazy_string str("lowercasE");
        EXPECT_TRUE(transformer::lowercase::transform(str));
        EXPECT_STREQ(str.data(), "lowercase");
    }

    {
        lazy_string str("lowercasEasndasnjdkans1823712nka");
        EXPECT_TRUE(transformer::lowercase::transform(str));
        EXPECT_STREQ(str.data(), "lowercaseasndasnjdkans1823712nka");
    }
}

TEST(TestLowercase, InvalidTransform)
{
    {
        lazy_string str("l");
        EXPECT_FALSE(transformer::lowercase::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("le");
        EXPECT_FALSE(transformer::lowercase::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("lowercase");
        EXPECT_FALSE(transformer::lowercase::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("lowercase but it doesn't matter");
        EXPECT_FALSE(transformer::lowercase::transform(str));
        EXPECT_FALSE(str.modified());
    }
}
