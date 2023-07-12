// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/url_decode.hpp"

TEST(TestUrlDecode, NameAndID)
{
    EXPECT_STREQ(transformer::url_decode::name().data(), "url_decode");
    EXPECT_EQ(transformer::url_decode::id(), transformer_id::url_decode);
}

TEST(TestUrlDecode, EmptyString)
{
    lazy_string str("");
    EXPECT_FALSE(transformer::url_decode::transform(str));
    EXPECT_FALSE(str.modified());
}

TEST(TestUrlDecode, ValidTransform)
{
    // Functional
    {
        lazy_string str("slightly+encoded");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded");
    }

    {
        lazy_string str("slightly+encoded+");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded ");
    }

    {
        lazy_string str("slightly+encoded%20");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded ");
    }

    {
        lazy_string str("%01hex+encoder%0f%10%7f%ff");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "\x01hex encoder\x0f\x10\x7f\xff");
    }

    // Tricky
    {
        lazy_string str("slightly+encoded%");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded%");
    }

    {
        lazy_string str("slightly+encoded%2");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded%2");
    }

    {
        lazy_string str("%20%");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), " %");
    }

    {
        lazy_string str("+");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), " ");
    }

    // Fix a few bypasses
    {
        lazy_string str("%41");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "A");
    }

    {
        lazy_string str("%2541");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "%41");
    }

    {
        lazy_string str("%%34%31");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "%41");
    }

    {
        lazy_string str("%%341");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "%41");
    }

    {
        lazy_string str("%%550041");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "%U0041");
    }

    {
        lazy_string str("%%750041");
        EXPECT_TRUE(transformer::url_decode::transform(str));
        EXPECT_STREQ(str.data(), "%u0041");
    }
}

TEST(TestUrlDecode, InvalidTransform)
{
    {
        lazy_string str("%");
        EXPECT_FALSE(transformer::url_decode::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("%u1234");
        EXPECT_FALSE(transformer::url_decode::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("l");
        EXPECT_FALSE(transformer::url_decode::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("le");
        EXPECT_FALSE(transformer::url_decode::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("url_decode");
        EXPECT_FALSE(transformer::url_decode::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("url_decode but it doesn't matter");
        EXPECT_FALSE(transformer::url_decode::transform(str));
        EXPECT_FALSE(str.modified());
    }
}

TEST(TestUrlDecodeIis, NameAndID)
{
    EXPECT_STREQ(transformer::url_decode_iis::name().data(), "url_decode_iis");
    EXPECT_EQ(transformer::url_decode_iis::id(), transformer_id::url_decode_iis);
}

TEST(TestUrlDecodeIis, EmptyString)
{
    lazy_string str("");
    EXPECT_FALSE(transformer::url_decode_iis::transform(str));
    EXPECT_FALSE(str.modified());
}

TEST(TestUrlDecodeIis, ValidTransform)
{
    // Functional
    {
        lazy_string str("slightly+encoded");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded");
    }

    {
        lazy_string str("slightly+encoded+");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded ");
    }

    {
        lazy_string str("slightly+encoded%20");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded ");
    }

    {
        lazy_string str("%01hex+encoder%0f%10%7f%ff");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "\x01hex encoder\x0f\x10\x7f\xff");
    }

    // Tricky
    {
        lazy_string str("slightly+encoded%");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded%");
    }

    {
        lazy_string str("slightly+encoded%2");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "slightly encoded%2");
    }

    {
        lazy_string str("%20%");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), " %");
    }

    {
        lazy_string str("+");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), " ");
    }

    // IIS Specific
    {
        lazy_string str("%u1234");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "\xE1\x88\xB4");
    }

    {
        lazy_string str("%u0041");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "A");
    }
    // Fix a few bypasses
    {
        lazy_string str("%41");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "A");
    }

    {
        lazy_string str("%2541");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "A");
    }

    {
        lazy_string str("%%34%31");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "A");
    }

    {
        lazy_string str("%%341");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "A");
    }

    {
        lazy_string str("%%550041");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "A");
    }

    {
        lazy_string str("%%750041");
        EXPECT_TRUE(transformer::url_decode_iis::transform(str));
        EXPECT_STREQ(str.data(), "A");
    }
}

TEST(TestUrlDecodeIis, InvalidTransform)
{
    {
        lazy_string str("%");
        EXPECT_FALSE(transformer::url_decode_iis::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("%u");
        EXPECT_FALSE(transformer::url_decode_iis::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("%u1");
        EXPECT_FALSE(transformer::url_decode_iis::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("%u41");
        EXPECT_FALSE(transformer::url_decode_iis::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("%u041");
        EXPECT_FALSE(transformer::url_decode_iis::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("l");
        EXPECT_FALSE(transformer::url_decode_iis::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("le");
        EXPECT_FALSE(transformer::url_decode_iis::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("url_decode");
        EXPECT_FALSE(transformer::url_decode_iis::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("url_decode but it doesn't matter");
        EXPECT_FALSE(transformer::url_decode_iis::transform(str));
        EXPECT_FALSE(str.modified());
    }
}
