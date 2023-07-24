// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/url_decode.hpp"
#include "transformer_utils.hpp"

TEST(TestUrlDecode, NameAndID)
{
    EXPECT_STREQ(transformer::url_decode::name().data(), "url_decode");
    EXPECT_EQ(transformer::url_decode::id(), transformer_id::url_decode);
}

TEST(TestUrlDecode, EmptyString) { EXPECT_NO_TRANSFORM(url_decode, ""); }

TEST(TestUrlDecode, ValidTransform)
{
    // Functional
    EXPECT_TRANSFORM(url_decode, "slightly+encoded", "slightly encoded");
    EXPECT_TRANSFORM(url_decode, "slightly+encoded+", "slightly encoded ");
    EXPECT_TRANSFORM(url_decode, "slightly+encoded%20", "slightly encoded ");
    EXPECT_TRANSFORM(url_decode, "%01hex+encoder%0f%10%7f%ff", "\x01hex encoder\x0f\x10\x7f\xff");
    // Tricky
    EXPECT_TRANSFORM(url_decode, "slightly+encoded%", "slightly encoded%");
    EXPECT_TRANSFORM(url_decode, "slightly+encoded%2", "slightly encoded%2");
    EXPECT_TRANSFORM(url_decode, "%20%", " %");
    EXPECT_TRANSFORM(url_decode, "+", " ");
    // Fix a few bypasses
    EXPECT_TRANSFORM(url_decode, "%41", "A");
    EXPECT_TRANSFORM(url_decode, "%2541", "%41");
    EXPECT_TRANSFORM(url_decode, "%%34%31", "%41");
    EXPECT_TRANSFORM(url_decode, "%%341", "%41");
    EXPECT_TRANSFORM(url_decode, "%%550041", "%U0041");
    EXPECT_TRANSFORM(url_decode, "%%750041", "%u0041");
}

TEST(TestUrlDecode, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(url_decode, "%");
    EXPECT_NO_TRANSFORM(url_decode, "%u1234");
    EXPECT_NO_TRANSFORM(url_decode, "l");
    EXPECT_NO_TRANSFORM(url_decode, "le");
    EXPECT_NO_TRANSFORM(url_decode, "url_decode");
    EXPECT_NO_TRANSFORM(url_decode, "url_decode but it doesn't matter");
}

TEST(TestUrlDecodeIis, NameAndID)
{
    EXPECT_STREQ(transformer::url_decode_iis::name().data(), "url_decode_iis");
    EXPECT_EQ(transformer::url_decode_iis::id(), transformer_id::url_decode_iis);
}

TEST(TestUrlDecodeIis, EmptyString) { EXPECT_NO_TRANSFORM(url_decode_iis, ""); }

TEST(TestUrlDecodeIis, ValidTransform)
{
    // Functional
    EXPECT_TRANSFORM(url_decode_iis, "slightly+encoded", "slightly encoded");
    EXPECT_TRANSFORM(url_decode_iis, "slightly+encoded+", "slightly encoded ");
    EXPECT_TRANSFORM(url_decode_iis, "slightly+encoded%20", "slightly encoded ");
    EXPECT_TRANSFORM(
        url_decode_iis, "%01hex+encoder%0f%10%7f%ff", "\x01hex encoder\x0f\x10\x7f\xff");
    // Tricky
    EXPECT_TRANSFORM(url_decode_iis, "slightly+encoded%", "slightly encoded%");
    EXPECT_TRANSFORM(url_decode_iis, "slightly+encoded%2", "slightly encoded%2");
    EXPECT_TRANSFORM(url_decode_iis, "%20%", " %");
    EXPECT_TRANSFORM(url_decode_iis, "+", " ");
    // IIS Specific
    EXPECT_TRANSFORM(url_decode_iis, "%u1234", "\xE1\x88\xB4");
    EXPECT_TRANSFORM(url_decode_iis, "%u0041", "A");
    // Fix a few bypasses
    EXPECT_TRANSFORM(url_decode_iis, "%41", "A");
    EXPECT_TRANSFORM(url_decode_iis, "%2541", "A");
    EXPECT_TRANSFORM(url_decode_iis, "%%34%31", "A");
    EXPECT_TRANSFORM(url_decode_iis, "%%341", "A");
    EXPECT_TRANSFORM(url_decode_iis, "%%550041", "A");
    EXPECT_TRANSFORM(url_decode_iis, "%%750041", "A");
}

TEST(TestUrlDecodeIis, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(url_decode_iis, "%");
    EXPECT_NO_TRANSFORM(url_decode_iis, "%u");
    EXPECT_NO_TRANSFORM(url_decode_iis, "%u1");
    EXPECT_NO_TRANSFORM(url_decode_iis, "%u41");
    EXPECT_NO_TRANSFORM(url_decode_iis, "%u041");
    EXPECT_NO_TRANSFORM(url_decode_iis, "l");
    EXPECT_NO_TRANSFORM(url_decode_iis, "le");
    EXPECT_NO_TRANSFORM(url_decode_iis, "url_decode");
    EXPECT_NO_TRANSFORM(url_decode_iis, "url_decode but it doesn't matter");
}
