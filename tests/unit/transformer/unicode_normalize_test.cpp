// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/unicode_normalize.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestUnicodeNormalize, NameAndID)
{
    EXPECT_STR(transformer::unicode_normalize::name(), "unicode_normalize");
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

    {
        std::string original;
        std::string result;
        for (unsigned i = 0; i < 1024; ++i) {
            result += "2/5";
            original += "⅖";
        }

        cow_string str(original);
        EXPECT_TRUE(transformer::unicode_normalize::transform(str));
        EXPECT_STR(str, result);
    }
}

TEST(TestUnicodeNormalize, HiddenASCIIRangeTransform)
{
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\x81", "\x01");

    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA0", " ");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA1", "!");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA2", "\"");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA3", "#");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA4", "$");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA5", "%");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA6", "&");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA7", "'");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA8", "(");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xA9", ")");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xAA", "*");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xAB", "+");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xAC", ",");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xAD", "-");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xAE", ".");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xAF", "/");

    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB0", "0");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB1", "1");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB2", "2");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB3", "3");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB4", "4");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB5", "5");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB6", "6");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB7", "7");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB8", "8");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xB9", "9");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xBA", ":");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xBB", ";");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xBC", "<");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xBD", "=");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xBE", ">");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x80\xBF", "?");

    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x80", "@");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x81", "A");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x82", "B");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x83", "C");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x84", "D");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x85", "E");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x86", "F");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x87", "G");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x88", "H");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x89", "I");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x8A", "J");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x8B", "K");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x8C", "L");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x8D", "M");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x8E", "N");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x8F", "O");

    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x90", "P");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x91", "Q");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x92", "R");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x93", "S");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x94", "T");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x95", "U");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x96", "V");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x97", "W");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x98", "X");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x99", "Y");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x9A", "Z");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x9B", "[");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x9C", "\\");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x9D", "]");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x9E", "^");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\x9F", "_");

    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA0", "`");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA1", "a");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA2", "b");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA3", "c");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA4", "d");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA5", "e");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA6", "f");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA7", "g");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA8", "h");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xA9", "i");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xAA", "j");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xAB", "k");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xAC", "l");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xAD", "m");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xAE", "n");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xAF", "o");

    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB0", "p");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB1", "q");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB2", "r");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB3", "s");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB4", "t");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB5", "u");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB6", "v");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB7", "w");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB8", "x");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xB9", "y");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xBA", "z");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xBB", "{");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xBC", "|");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xBD", "}");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xBE", "~");
    EXPECT_TRANSFORM(unicode_normalize, "\xF3\xA0\x81\xBF", "\x7F");
}

TEST(TestUnicodeNormalize, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(unicode_normalize, "u");
    EXPECT_NO_TRANSFORM(unicode_normalize, "`");
    EXPECT_NO_TRANSFORM(unicode_normalize, "unicode_normalize");
    EXPECT_NO_TRANSFORM(unicode_normalize, "unicode_normalize but it doesn't matter");
}

} // namespace
