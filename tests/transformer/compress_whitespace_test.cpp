// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"

TEST(TestCompressWhitespace, NameAndID)
{
    EXPECT_STREQ(transformer::compress_whitespace::name().data(), "compress_whitespace");
    EXPECT_EQ(transformer::compress_whitespace::id(), transformer_id::compress_whitespace);
}

TEST(TestCompressWhitespace, EmptyString)
{
    lazy_string str("");
    EXPECT_FALSE(transformer::compress_whitespace::transform(str));
    EXPECT_STREQ(str.get(), nullptr);
}

TEST(TestCompressWhitespace, ValidTransform)
{
    {
        lazy_string str("  c");
        EXPECT_TRUE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), " c");
    }

    {
        lazy_string str("c  w");
        EXPECT_TRUE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), "c w");
    }

    {
        lazy_string str("c  ");
        EXPECT_TRUE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), "c ");
    }

    {
        lazy_string str("  c  ");
        EXPECT_TRUE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), " c ");
    }

    {
        lazy_string str("        c");
        EXPECT_TRUE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), " c");
    }

    {
        lazy_string str("c      w");
        EXPECT_TRUE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), "c w");
    }

    {
        lazy_string str("c      ");
        EXPECT_TRUE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), "c ");
    }

    {
        lazy_string str("      c     ");
        EXPECT_TRUE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), " c ");
    }

    {
        lazy_string str("      compress  white     space transformer     ");
        EXPECT_TRUE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), " compress white space transformer ");
    }
}

TEST(TestCompressWhitespace, InvalidTransform)
{
    {
        lazy_string str("c");
        EXPECT_FALSE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), nullptr);
    }

    {
        lazy_string str(" c");
        EXPECT_FALSE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), nullptr);
    }

    {
        lazy_string str("c ");
        EXPECT_FALSE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), nullptr);
    }

    {
        lazy_string str(" c ");
        EXPECT_FALSE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), nullptr);
    }

    {
        lazy_string str("c w");
        EXPECT_FALSE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), nullptr);
    }

    {
        lazy_string str("compress_whitespace");
        EXPECT_FALSE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), nullptr);
    }

    {
        lazy_string str("compress_whitespace but it doesn't matter");
        EXPECT_FALSE(transformer::compress_whitespace::transform(str));
        EXPECT_STREQ(str.get(), nullptr);
    }
}
