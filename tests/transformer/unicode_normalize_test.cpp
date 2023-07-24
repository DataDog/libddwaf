// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/unicode_normalize.hpp"

TEST(TestUnicodeNormalize, NameAndID)
{
    EXPECT_STREQ(transformer::unicode_normalize::name().data(), "unicode_normalize");
    EXPECT_EQ(transformer::unicode_normalize::id(), transformer_id::unicode_normalize);
}

TEST(TestUnicodeNormalize, EmptyString)
{
    cow_string str("");
    EXPECT_FALSE(transformer::unicode_normalize::transform(str));
    EXPECT_FALSE(str.modified());
}

TEST(TestUnicodeNormalize, ValidTransform)
{
    {
        cow_string str("⃝");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        cow_string str("ß");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "ss");
    }

    {
        cow_string str("é");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "e");
    }

    {
        cow_string str("ı");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "i");
    }

    {
        cow_string str("–");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "-");
    }

    {
        cow_string str("—");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "-");
    }

    {
        cow_string str("⁵");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "5");
    }

    {
        cow_string str("⅖");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "2/5");
    }

    {
        cow_string str("ﬁ");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "fi");
    }

    {
        cow_string str("𝑎");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "a");
    }

    {
        cow_string str("Å👨‍👩‍👧‍👦");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "A👨‍👩‍👧‍👦");
    }

    {
        cow_string str("👨‍👩‍👧‍👦Å");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "👨‍👩‍👧‍👦A");
    }

    {
        cow_string str("Aa𝑎éßıﬁ2⁵—⅖");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "Aaaessifi25-2/5");
    }

    {
        cow_string str("Aẞé");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "ASSe");
    }

    {
        cow_string str("Àße");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "Asse");
    }

    {
        cow_string str("${${::-j}nd${upper:ı}:gopher//127.0.0.1:1389}");
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STREQ(str.data(), "${${::-j}nd${upper:i}:gopher//127.0.0.1:1389}");
    }
}

TEST(TestUnicodeNormalize, InvalidTransform)
{
    {
        cow_string str("u");
        EXPECT_FALSE(transformer::unicode_normalize::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("`");
        EXPECT_FALSE(transformer::unicode_normalize::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("unicode_normalize");
        EXPECT_FALSE(transformer::unicode_normalize::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("unicode_normalize but it doesn't matter");
        EXPECT_FALSE(transformer::unicode_normalize::transform(str));
        EXPECT_FALSE(str.modified());
    }
}
