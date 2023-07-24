// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/unicode_normalize.hpp"
#include "transformer_utils.hpp"

TEST(TestUnicodeNormalize, NameAndID)
{
    EXPECT_STREQ(transformer::unicode_normalize::name().data(), "unicode_normalize");
    EXPECT_EQ(transformer::unicode_normalize::id(), transformer_id::unicode_normalize);
}

TEST(TestUnicodeNormalize, EmptyString) { EXPECT_NO_TRANSFORM(unicode_normalize, ""); }

TEST(TestUnicodeNormalize, ValidTransform)
{
    EXPECT_TRANSFORM(unicode_normalize, "⃝", "");
    EXPECT_TRANSFORM(unicode_normalize, "ß", "ss");
    EXPECT_TRANSFORM(unicode_normalize, "é", "e");
    EXPECT_TRANSFORM(unicode_normalize, "ı", "i");
    EXPECT_TRANSFORM(unicode_normalize, "–", "-");
    EXPECT_TRANSFORM(unicode_normalize, "—", "-");
    EXPECT_TRANSFORM(unicode_normalize, "⁵", "5");
    EXPECT_TRANSFORM(unicode_normalize, "⅖", "2/5");
    EXPECT_TRANSFORM(unicode_normalize, "ﬁ", "fi");
    EXPECT_TRANSFORM(unicode_normalize, "𝑎", "a");
    EXPECT_TRANSFORM(
        unicode_normalize, "Å👨‍👩‍👧‍👦", "A👨‍👩‍👧‍👦");
    EXPECT_TRANSFORM(
        unicode_normalize, "👨‍👩‍👧‍👦Å", "👨‍👩‍👧‍👦A");
    EXPECT_TRANSFORM(unicode_normalize, "Aa𝑎éßıﬁ2⁵—⅖", "Aaaessifi25-2/5");
    EXPECT_TRANSFORM(unicode_normalize, "Aẞé", "ASSe");
    EXPECT_TRANSFORM(unicode_normalize, "Àße", "Asse");
    EXPECT_TRANSFORM(unicode_normalize, "${${::-j}nd${upper:ı}:gopher//127.0.0.1:1389}",
        "${${::-j}nd${upper:i}:gopher//127.0.0.1:1389}");
}

TEST(TestUnicodeNormalize, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(unicode_normalize, "u");
    EXPECT_NO_TRANSFORM(unicode_normalize, "`");
    EXPECT_NO_TRANSFORM(unicode_normalize, "unicode_normalize");
    EXPECT_NO_TRANSFORM(unicode_normalize, "unicode_normalize but it doesn't matter");
}
