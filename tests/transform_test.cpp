// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"
#include <utf8.hpp>

namespace ddwaf::utf8 {
uint8_t codepoint_to_bytes(uint32_t codepoint, char *utf8_buffer);
}

void doesTransform(vector<PW_TRANSFORM_ID> ids, const char *sourceString,
    const char *transformedString, bool postCheck = true)
{
    ddwaf_object string;

    if (strlen(sourceString) == 0) {
        ddwaf_object_string(&string, sourceString);
    } else {
        // Remove the margin that ddwaf_object_string usually introduce to detect small overrun
        ddwaf_object_stringl(&string, sourceString, strlen(sourceString) - 1);
        ((char *)string.stringValue)[string.nbEntries] = sourceString[string.nbEntries];
        string.nbEntries += 1;
    }

    if (transformedString != NULL) {
        EXPECT_TRUE(PWTransformer::doesNeedTransform(ids, &string));
        for (const auto &trans : ids) EXPECT_TRUE(PWTransformer::transform(trans, &string));

        EXPECT_EQ(string.nbEntries, strlen(transformedString));

        // strcmp will usually overrun by one byte. That's not okay here
        if (string.nbEntries == strlen(transformedString))
            EXPECT_EQ(memcmp(string.stringValue, transformedString, string.nbEntries), 0);
        else
            EXPECT_STREQ(string.stringValue, transformedString);
    } else {
        EXPECT_FALSE(PWTransformer::doesNeedTransform(ids, &string));
        for (const auto &trans : ids) {
            EXPECT_TRUE(PWTransformer::transform(trans, &string));
            EXPECT_EQ(string.nbEntries, strlen(sourceString));
            EXPECT_EQ(memcmp(string.stringValue, sourceString, string.nbEntries), 0);
        }
    }

    if (postCheck) {
        EXPECT_FALSE(PWTransformer::doesNeedTransform(ids, &string));
    }

    ddwaf_object_free(&string);
}

bool shouldTransform(vector<PW_TRANSFORM_ID> ids, const char *sourceString)
{
    ddwaf_object string;
    ddwaf_object_string(&string, sourceString);
    bool output = PWTransformer::doesNeedTransform(ids, &string);
    ddwaf_object_free(&string);
    return output;
}

TEST(TestTransforms, TestBad)
{
    vector<PW_TRANSFORM_ID> ids({PWT_LOWERCASE, PWT_NONULL});
    ddwaf_object intInput = DDWAF_OBJECT_SIGNED_FORCE(42);

    EXPECT_FALSE(PWTransformer::transform(PWT_INVALID, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_LOWERCASE, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_NONULL, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_COMPRESS_WHITE, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_LENGTH, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_NORMALIZE, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_NORMALIZE_WIN, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_DECODE_URL, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_DECODE_URL_IIS, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_DECODE_CSS, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_DECODE_JS, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_DECODE_HTML, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_DECODE_BASE64, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_DECODE_BASE64_EXT, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_ENCODE_BASE64, &intInput));
    EXPECT_FALSE(PWTransformer::transform(PWT_CMDLINE, &intInput));

    intInput.type = DDWAF_OBJ_STRING;
    intInput.stringValue = NULL;
    EXPECT_FALSE(PWTransformer::transform(PWT_LOWERCASE, &intInput));

    ddwaf_object sInput;
    ddwaf_object_string(&sInput, "String");
    free((void *)sInput.stringValue);
    sInput.stringValue = NULL;

    for (const auto &transform : ids) {
        EXPECT_FALSE(PWTransformer::transform(transform, &sInput));
        EXPECT_FALSE(PWTransformer::transform(transform, &sInput));
    }

    sInput.parameterName = "";
    EXPECT_FALSE(PWTransformer::transform(PWT_NONULL, &sInput));
}

TEST(TestTransforms, TestNeedTransform)
{
    ddwaf_object string;
    ddwaf_object_string(&string, "String");
    ASSERT_TRUE(string.type == DDWAF_OBJ_STRING);

    // Has upper case
    EXPECT_FALSE(PWTransformer::doesNeedTransform({}, &string));
    EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_LOWERCASE}, &string));
    EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_NONULL}, &string));
    EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_LOWERCASE, PWT_NONULL}, &string));

    // Insert the final 0 into the "string"
    string.nbEntries += 1;
    EXPECT_FALSE(PWTransformer::doesNeedTransform({}, &string));
    EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_LOWERCASE}, &string));
    EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_NONULL}, &string));
    EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_LOWERCASE, PWT_NONULL}, &string));

    // Remove uppercase
    ((char *)string.stringValue)[0] = 's';
    EXPECT_FALSE(PWTransformer::doesNeedTransform({}, &string));
    EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_LOWERCASE}, &string));
    EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_NONULL}, &string));
    EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_LOWERCASE, PWT_NONULL}, &string));

    // Remove both the 0 and the uppercase
    string.nbEntries -= 1;
    EXPECT_FALSE(PWTransformer::doesNeedTransform({}, &string));
    EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_LOWERCASE}, &string));
    EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_NONULL}, &string));
    EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_LOWERCASE, PWT_NONULL}, &string));

    // Some edge cases
    EXPECT_FALSE(PWTransformer::doesNeedTransform({}, NULL));

    ddwaf_object number = DDWAF_OBJECT_UNSIGNED_FORCE(42);
    EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_LOWERCASE, PWT_NONULL}, &number));

    ddwaf_object_free(&string);
}

TEST(TestTransforms, TestCompressWhiteSpace)
{
    EXPECT_EQ(PWTransformer::getIDForString("compressWhiteSpace"), PWT_COMPRESS_WHITE);

    doesTransform({PWT_COMPRESS_WHITE}, "S t     r  i        n g      ", "S t r i n g ");
    // Regression, the accessed invalid memory with empty strings
    doesTransform({PWT_COMPRESS_WHITE}, "", NULL);

    ddwaf_object value = DDWAF_OBJECT_UNSIGNED_FORCE(42);
    EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_COMPRESS_WHITE}, &value));
}

TEST(TestTransforms, TestLength)
{
    EXPECT_EQ(PWTransformer::getIDForString("length"), PWT_LENGTH);

    ddwaf_object string;
    ddwaf_object_string(&string, "String");

    EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_LENGTH}, &string));
    EXPECT_TRUE(PWTransformer::transform(PWT_LENGTH, &string));

    EXPECT_EQ(string.type, DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(string.uintValue, 6);

    EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_LENGTH}, &string));
}

TEST(TestTransforms, TestNormalize)
{
    EXPECT_EQ(PWTransformer::getIDForString("normalizePath"), PWT_NORMALIZE);
    EXPECT_EQ(PWTransformer::getIDForString("normalizePathWin"), PWT_NORMALIZE_WIN);

    doesTransform({PWT_NORMALIZE}, "notAPath", NULL);
    doesTransform({PWT_NORMALIZE}, "A/Simple/Path", NULL);
    doesTransform({PWT_NORMALIZE}, "A/Simple/./Path", "A/Simple/Path");
    doesTransform({PWT_NORMALIZE}, "A/Simple/Wrong/../Path", "A/Simple/Path");
    doesTransform({PWT_NORMALIZE}, "A/Simple/Path/.", "A/Simple/Path/");
    doesTransform({PWT_NORMALIZE}, "A/Simple/Path/..", "A/Simple/");
    doesTransform({PWT_NORMALIZE}, "A/Simple/Path/bla.", NULL);
    doesTransform({PWT_NORMALIZE}, "A/Simple/.Path/bla.", NULL);
    doesTransform({PWT_NORMALIZE}, "A/Simple/../../../../bla.", "/bla.");
    doesTransform({PWT_NORMALIZE}, "./bla", "bla");

    doesTransform({PWT_NORMALIZE_WIN}, "notAPath", NULL);
    doesTransform({PWT_NORMALIZE_WIN}, "notA\\Path", "notA/Path");
    doesTransform({PWT_NORMALIZE_WIN}, "\\not/A\\Path", "/not/A/Path");
    doesTransform({PWT_NORMALIZE_WIN}, "A\\Simple/Path", "A/Simple/Path");
    doesTransform({PWT_NORMALIZE_WIN}, "A/Simple\\./Path", "A/Simple/Path");
    doesTransform({PWT_NORMALIZE_WIN}, "A/Simple/Wrong/..\\Path", "A/Simple/Path");
    doesTransform({PWT_NORMALIZE_WIN}, "A/Simple/Path\\.", "A/Simple/Path/");
    doesTransform({PWT_NORMALIZE_WIN}, "A/Simple/Path\\..", "A/Simple/");
    doesTransform({PWT_NORMALIZE_WIN}, "A/Simple/Path/bla.", NULL);
    doesTransform({PWT_NORMALIZE_WIN}, "A/Simple\\.Path/bla.", "A/Simple/.Path/bla.");
    doesTransform({PWT_NORMALIZE_WIN}, "A/Simple/../..\\..\\..\\bla.", "/bla.");
    doesTransform({PWT_NORMALIZE_WIN}, ".\\bla", "bla");

    ddwaf_object value = DDWAF_OBJECT_UNSIGNED_FORCE(42);
    EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_NORMALIZE_WIN}, &value));
}

TEST(TestTransforms, TestURLDecode)
{
    EXPECT_EQ(PWTransformer::getIDForString("urlDecode"), PWT_DECODE_URL);
    EXPECT_EQ(PWTransformer::getIDForString("urlDecodeUni"), PWT_DECODE_URL_IIS);

    // Functionnal
    doesTransform({PWT_DECODE_URL}, "not encoded", NULL);
    doesTransform({PWT_DECODE_URL}, "slightly+encoded", "slightly encoded");
    doesTransform({PWT_DECODE_URL}, "slightly+encoded+", "slightly encoded ");
    doesTransform({PWT_DECODE_URL}, "slightly+encoded%20", "slightly encoded ");
    doesTransform(
        {PWT_DECODE_URL}, "%01hex+encoder%0f%10%7f%ff", "\x01hex encoder\x0f\x10\x7f\xff");

    // Tricky
    doesTransform({PWT_DECODE_URL}, "+", " ");
    doesTransform({PWT_DECODE_URL}, "%", NULL);
    doesTransform({PWT_DECODE_URL}, "slightly+encoded%", "slightly encoded%");
    doesTransform({PWT_DECODE_URL}, "slightly+encoded%2", "slightly encoded%2");
    doesTransform({PWT_DECODE_URL}, "%20%", " %");

    // IIS use the same logic so let's focus on the new bits
    doesTransform({PWT_DECODE_URL}, "%u1234", NULL);
    doesTransform({PWT_DECODE_URL_IIS}, "%u1234", "\xE1\x88\xB4");
    doesTransform({PWT_DECODE_URL_IIS}, "%", NULL);
    doesTransform({PWT_DECODE_URL_IIS}, "%u", NULL);
    doesTransform({PWT_DECODE_URL_IIS}, "%u1", NULL);
    doesTransform({PWT_DECODE_URL_IIS}, "%u41", NULL);
    doesTransform({PWT_DECODE_URL_IIS}, "%u041", NULL);
    doesTransform({PWT_DECODE_URL_IIS}, "%u0041", "A");

    // Fix a few bypasses
    doesTransform({PWT_DECODE_URL}, "%41", "A");

    doesTransform({PWT_DECODE_URL}, "%2541", "%41", false);
    doesTransform({PWT_DECODE_URL_IIS}, "%2541", "A");

    doesTransform({PWT_DECODE_URL}, "%%34%31", "%41", false);
    doesTransform({PWT_DECODE_URL_IIS}, "%%34%31", "A");

    doesTransform({PWT_DECODE_URL}, "%%341", "%41", false);
    doesTransform({PWT_DECODE_URL_IIS}, "%%341", "A");

    doesTransform({PWT_DECODE_URL}, "%%550041", "%U0041");
    doesTransform({PWT_DECODE_URL_IIS}, "%%550041", "A");

    doesTransform({PWT_DECODE_URL}, "%%750041", "%u0041");
    doesTransform({PWT_DECODE_URL_IIS}, "%%550041", "A");
}

TEST(TestTransforms, TestCSSDecode)
{
    EXPECT_EQ(PWTransformer::getIDForString("cssDecode"), PWT_DECODE_CSS);

    doesTransform({PWT_DECODE_CSS}, "no CSS transformations", NULL);
    doesTransform({PWT_DECODE_CSS}, "\\00\\d800\\dfff\\110000 CSS transformations",
        "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD"
        "CSS transformations");
    doesTransform({PWT_DECODE_CSS}, "CSS\\ff01  transformations\\e9",
        "CSS\xEF\xBC\x81 transformations\xC3\xA9");
    doesTransform(
        {PWT_DECODE_CSS}, "CSS\\77transformations\\14242", "CSSwtransformations\xF0\x94\x89\x82");
    doesTransform({PWT_DECODE_CSS}, "CSS\\\n tran\\sformations", "CSS transformations");
    doesTransform({PWT_DECODE_CSS}, "\\0SS\\0  transformations", "SS\xEF\xBF\xBD transformations");

    doesTransform(
        {PWT_DECODE_URL, PWT_DECODE_CSS}, "CSS\\%0a tran\\sformations", "CSS transformations");
    doesTransform({PWT_DECODE_URL, PWT_DECODE_CSS}, "CSS transformations\\", "CSS transformations");
}

TEST(TestTransforms, TestJSDecode)
{
    EXPECT_EQ(PWTransformer::getIDForString("jsDecode"), PWT_DECODE_JS);

    doesTransform({PWT_DECODE_JS}, "no JS transformations", NULL);
    doesTransform({PWT_DECODE_JS}, "no JS\\x20transformations\\", "no JS transformations\\");
    doesTransform({PWT_DECODE_JS}, "no \\JS\\ttransformations", "no JS\ttransformations");
    doesTransform({PWT_DECODE_JS}, "\\a\\b\\c\\f\\n\\r\\t\\v\\z\\x\\u", "\a\bc\f\n\r\t\vz");
    doesTransform(
        {PWT_DECODE_JS}, "\\x41\\x20\\x4aS\\x20transf\\x6Frmations", "A JS transformations");
    doesTransform({PWT_DECODE_JS}, "\\u0041 JS \\ud83e\\udd14 transformations\\uff01",
        "A JS \xf0\x9f\xa4\x94 transformations\xEF\xBC\x81");

    doesTransform({PWT_DECODE_JS}, "Test \\udbff\\udfff", "Test \xF4\x8F\xBF\xBF");
    doesTransform({PWT_DECODE_JS}, "Test\\x20\\", "Test \\");
    doesTransform({PWT_DECODE_JS}, "Test\\x20\\ ", "Test  ");
    doesTransform({PWT_DECODE_JS}, "Test\\x20\\x", "Test ");
    doesTransform({PWT_DECODE_JS}, "Test\\x20\\u", "Test ");
    doesTransform({PWT_DECODE_JS}, "Test\\x20\\ud801", "Test \xef\xbf\xbd");

    {
        char fakeBuffer[16] = {0};
        EXPECT_EQ(utf8::codepoint_to_bytes(0x200000, fakeBuffer), 0);
    }
}

TEST(TestTransforms, TestHTMLDecode)
{
    EXPECT_EQ(PWTransformer::getIDForString("htmlEntityDecode"), PWT_DECODE_HTML);

    doesTransform({PWT_DECODE_HTML}, "no HTML transformations", NULL);
    doesTransform({PWT_DECODE_HTML}, "no HTML &&transformations", NULL);
    doesTransform({PWT_DECODE_HTML}, "no &ampblaHTML transformations", NULL);
    doesTransform({PWT_DECODE_HTML}, "no", NULL);

    doesTransform({PWT_DECODE_HTML},
        "HTML &#x0000000000000000000000000000041 &#x41; transformation", "HTML A A transformation");
    doesTransform({PWT_DECODE_HTML}, "HTML &#0000000000000000000000000000065 &#65; transformation",
        "HTML A A transformation");

    doesTransform({PWT_DECODE_HTML}, "&lt;&gt;&amp;&quot;&nbsp;", "<>&\"\xa0");
    doesTransform({PWT_DECODE_HTML}, "&#x41 :) &#x &#X &# &#xffffffff &#999999999 &lt",
        "A :) &#x &#X &# \xEF\xBF\xBD \xEF\xBF\xBD &lt");

    doesTransform({PWT_DECODE_HTML}, "&#x41;", "A");
    doesTransform({PWT_DECODE_HTML}, "&#x41", "A");
    doesTransform({PWT_DECODE_HTML}, "&#65;", "A");
    doesTransform({PWT_DECODE_HTML}, "&#65", "A");
    doesTransform({PWT_DECODE_HTML}, "&lt;", "<");

    doesTransform({PWT_DECODE_HTML}, "HTML &#xffffff fffff &#x41; transformation",
        "HTML \xef\xbf\xbd fffff A transformation");
    doesTransform({PWT_DECODE_HTML}, "HTML &#xffffffffff9fff fffff &#x41; transformation",
        "HTML \xef\xbf\xbd fffff A transformation");
    doesTransform({PWT_DECODE_HTML}, "HTML &#9999999 99999 &#x41; transformation",
        "HTML \xef\xbf\xbd 99999 A transformation");
    doesTransform({PWT_DECODE_HTML}, "HTML &#9999999ffff 99999 &#x41; transformation",
        "HTML \xef\xbf\xbd"
        "ffff 99999 A transformation");
}

TEST(TestTransforms, TestB64DecodeValidation)
{
    EXPECT_EQ(PWTransformer::getIDForString("base64Decode"), PWT_DECODE_BASE64);
    EXPECT_EQ(PWTransformer::getIDForString("base64DecodeExt"), PWT_DECODE_BASE64_EXT);

    EXPECT_FALSE(shouldTransform({PWT_DECODE_BASE64}, "normal sentence"));
    EXPECT_FALSE(shouldTransform({PWT_DECODE_BASE64_EXT}, "normal sentence"));

    EXPECT_TRUE(shouldTransform({PWT_DECODE_BASE64}, "normalsentence"));
    EXPECT_TRUE(shouldTransform({PWT_DECODE_BASE64}, "normalsentence="));
    EXPECT_TRUE(shouldTransform({PWT_DECODE_BASE64}, "normalsentence=="));
    EXPECT_FALSE(shouldTransform({PWT_DECODE_BASE64}, "normalsentence==="));
    EXPECT_TRUE(shouldTransform({PWT_DECODE_BASE64_EXT}, "normal sentence=="));
}

TEST(TestTransforms, TestB64Decode)
{
    // The two base64 modes share the same decoder
    doesTransform({PWT_DECODE_BASE64}, "Zm9vYmFy", "foobar", false);
    doesTransform({PWT_DECODE_BASE64}, "Zm9vYmE=", "fooba", false);
    doesTransform({PWT_DECODE_BASE64}, "Zm9vYg==", "foob", false);
    doesTransform({PWT_DECODE_BASE64}, "Zm9v", "foo", false);
    doesTransform({PWT_DECODE_BASE64}, "Zm8=", "fo", false);
    doesTransform({PWT_DECODE_BASE64}, "Zg==", "f", false);
    doesTransform({PWT_DECODE_BASE64}, "Z===", "d", false);
    doesTransform({PWT_DECODE_BASE64}, "ZA==", "d", false);
    doesTransform({PWT_DECODE_BASE64}, "ZAA=", "d", false);

    doesTransform({PWT_DECODE_BASE64}, "Zm9vYmF", "fooba@", false);
    doesTransform({PWT_DECODE_BASE64_EXT}, "Zm==============9v", "foo", false);
}

TEST(TestTransforms, TestB64Encode)
{
    EXPECT_EQ(PWTransformer::getIDForString("base64Encode"), PWT_ENCODE_BASE64);

    // Simple test vectors
    doesTransform({PWT_ENCODE_BASE64}, "foobar", "Zm9vYmFy", false);
    doesTransform({PWT_ENCODE_BASE64}, "fooba", "Zm9vYmE=", false);
    doesTransform({PWT_ENCODE_BASE64}, "foob", "Zm9vYg==", false);
    doesTransform({PWT_ENCODE_BASE64}, "foo", "Zm9v", false);
    doesTransform({PWT_ENCODE_BASE64}, "fo", "Zm8=", false);
    doesTransform({PWT_ENCODE_BASE64}, "f", "Zg==", false);
    doesTransform({PWT_ENCODE_BASE64}, "d", "ZA==", false);
    // Regression, negative characters resulted in a buffer overflow
    doesTransform({PWT_ENCODE_BASE64}, "\x80\x80\x80\x80\x80\x80", "gICAgICA", false);

    // Cover a few edge cases
    {
        // Trying to base64Encode a non-string literal
        ddwaf_object arg = DDWAF_OBJECT_SIGNED_FORCE(42);
        EXPECT_FALSE(PWTransformer::transform(PWT_ENCODE_BASE64, &arg));

        // Trying to base64Encode an empty string
        arg.type = DDWAF_OBJ_STRING;
        arg.stringValue = NULL;
        EXPECT_FALSE(PWTransformer::transform(PWT_ENCODE_BASE64, &arg));

        arg.nbEntries = 0;
        arg.stringValue = "string";
        EXPECT_FALSE(PWTransformer::transform(PWT_ENCODE_BASE64, &arg));

        // Trying to base64Encode a parameter that would trigger an overflow
        arg.nbEntries = UINT64_MAX / 4 * 3;
        EXPECT_FALSE(PWTransformer::transform(PWT_ENCODE_BASE64, &arg));
    }
}

TEST(TestTransforms, TestCmdLine)
{
    EXPECT_EQ(PWTransformer::getIDForString("cmdLine"), PWT_CMDLINE);

    // Functionnal tests
    doesTransform({PWT_CMDLINE}, "normal sentence(really)", NULL);
    doesTransform({PWT_CMDLINE}, "normal sentence (really)", "normal sentence(really)");
    doesTransform({PWT_CMDLINE}, "normal sentence /really", "normal sentence/really");
    doesTransform({PWT_CMDLINE}, "normal\\ sent\"enc'e re^ally", "normal sentence really");
    doesTransform({PWT_CMDLINE}, "normal;sentence,really", "normal sentence really");
    doesTransform({PWT_CMDLINE}, "normal; sentence, really", "normal sentence really");
    doesTransform(
        {PWT_CMDLINE}, "normal sentence \t \v \f \n \r  really", "normal sentence really");
    doesTransform({PWT_CMDLINE}, "normal sentence REALLY", "normal sentence really");

    // More aggressive corner case validation
    doesTransform(
        {PWT_CMDLINE}, "normal sentence \t \v \f \n \r  (really)", "normal sentence(really)");
    doesTransform({PWT_CMDLINE}, "bla '", "bla ");
    doesTransform({PWT_CMDLINE}, "bla ;", "bla ");
    doesTransform({PWT_CMDLINE}, "bla /", "bla/");
    doesTransform({PWT_CMDLINE}, "bLaBlAbLa", "blablabla");
    doesTransform({PWT_CMDLINE}, "BlAbLaBlA", "blablabla");
}

TEST(TestTransforms, TestNumerize)
{
    EXPECT_EQ(PWTransformer::getIDForString("numerize"), PWT_NUMERIZE);

    // Not numbers
    EXPECT_FALSE(shouldTransform({PWT_NUMERIZE}, "not a number"));
    EXPECT_FALSE(shouldTransform({PWT_NUMERIZE}, "-bla"));
    EXPECT_FALSE(shouldTransform({PWT_NUMERIZE}, " 12345"));
    EXPECT_FALSE(shouldTransform({PWT_NUMERIZE}, "-"));

    // Check value
    {
        ddwaf_object arg;
        ddwaf_object_string(&arg, "0");
        EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_NUMERIZE}, &arg));
        EXPECT_TRUE(PWTransformer::transform(PWT_NUMERIZE, &arg));
        EXPECT_EQ(arg.type, DDWAF_OBJ_UNSIGNED);
        EXPECT_EQ(arg.uintValue, 0);
    }
    {
        ddwaf_object arg;
        ddwaf_object_string(&arg, "1");
        EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_NUMERIZE}, &arg));
        EXPECT_TRUE(PWTransformer::transform(PWT_NUMERIZE, &arg));
        EXPECT_EQ(arg.type, DDWAF_OBJ_UNSIGNED);
        EXPECT_EQ(arg.uintValue, 1);
    }
    {
        ddwaf_object arg;
        ddwaf_object_string(&arg, "-1");
        EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_NUMERIZE}, &arg));
        EXPECT_TRUE(PWTransformer::transform(PWT_NUMERIZE, &arg));
        EXPECT_EQ(arg.type, DDWAF_OBJ_SIGNED);
        EXPECT_EQ(arg.uintValue, -1);
    }
    {
        ddwaf_object arg;
        ddwaf_object_string(&arg, "-9223372036854775807");
        EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_NUMERIZE}, &arg));
        EXPECT_TRUE(PWTransformer::transform(PWT_NUMERIZE, &arg));
        EXPECT_EQ(arg.type, DDWAF_OBJ_SIGNED);
        EXPECT_EQ(arg.intValue, -INT64_MAX);
    }
    {
        ddwaf_object arg;
        ddwaf_object_string(&arg, "18446744073709551615");
        EXPECT_TRUE(PWTransformer::doesNeedTransform({PWT_NUMERIZE}, &arg));
        EXPECT_TRUE(PWTransformer::transform(PWT_NUMERIZE, &arg));
        EXPECT_EQ(arg.type, DDWAF_OBJ_UNSIGNED);
        EXPECT_EQ(arg.uintValue, UINT64_MAX);
    }

    // Too large number
    EXPECT_FALSE(shouldTransform({PWT_NUMERIZE}, "-9223372036854775808"));

    // Invalid payload
    {
        ddwaf_object arg = DDWAF_OBJECT_SIGNED_FORCE(42);
        EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_NUMERIZE}, &arg));
    }
    {
        ddwaf_object arg;
        ddwaf_object_stringl(&arg, "NULL", 0);
        EXPECT_FALSE(PWTransformer::doesNeedTransform({PWT_NUMERIZE}, &arg));
        ddwaf_object_free(&arg);
    }
}

TEST(TestTransforms, TestRemoveComments)
{
    EXPECT_EQ(PWTransformer::getIDForString("removeComments"), PWT_REMOVE_COMMENTS);

    // Test full-string comment
    // Note: some ofthese tests cannot be performed as runTransform doesn't
    //     support a legitimate return value of 0.
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "/*foo*/"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "<!--foo-->"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "#foo"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "--foo"));
    doesTransform({PWT_REMOVE_COMMENTS}, "/*foo*/", "");
    doesTransform({PWT_REMOVE_COMMENTS}, "<!--foo-->", "");
    doesTransform({PWT_REMOVE_COMMENTS}, "#foo", "");
    doesTransform({PWT_REMOVE_COMMENTS}, "--foo", "");

    // Test beginning comment
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "/*foo*/bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "<!--foo-->bar"));
    doesTransform({PWT_REMOVE_COMMENTS}, "/*foo*/bar", "bar");
    doesTransform({PWT_REMOVE_COMMENTS}, "<!--foo-->bar", "bar");

    // Test end comment
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar#foo"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar--foo"));
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/", "bar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->", "bar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar--foo", "bar");

    // Test middle comment
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->bar"));
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/bar", "barbar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->bar", "barbar");

    // Test consecutive comments
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*//*foo*/bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/<!--foo-->bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo--><!--foo-->bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->/*foo*/bar"));
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*//*foo*/bar", "barbar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/<!--foo-->bar", "barbar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo--><!--foo-->bar", "barbar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->/*foo*/bar", "barbar");

    // Test multiple comments
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/bar/*foo*/bar#foo"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/bar<!--foo-->bar--foo"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->bar<!--foo-->bar#foo"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->bar/*foo*/bar--foo"));
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/bar/*foo*/bar#foo", "barbarbar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*foo*/bar<!--foo-->bar--foo", "barbarbar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->bar<!--foo-->bar#foo", "barbarbar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo-->bar/*foo*/bar--foo", "barbarbar");

    //// Test nested comments
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*<!--foo-->*/bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*/*foo*/*/bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--/*foo*/-->bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--<!--foo-->-->bar"));
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*<!--foo-->*/bar", "barbar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*/*foo*/*/bar", "bar*/bar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--/*foo*/-->bar", "barbar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--<!--foo-->-->bar", "bar");

    // Test missing comment terminator
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*foo bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo bar"));
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*foo bar", "bar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--foo bar", "bar");

    // Test comment start at end of string
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar/*"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar<!--"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar#"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "bar--"));
    doesTransform({PWT_REMOVE_COMMENTS}, "bar/*", "bar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar<!--", "bar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar#", "bar");
    doesTransform({PWT_REMOVE_COMMENTS}, "bar--", "bar");

    // Test empty comments
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "foo/**/bar"));
    EXPECT_TRUE(shouldTransform({PWT_REMOVE_COMMENTS}, "foo<!---->bar"));
    doesTransform({PWT_REMOVE_COMMENTS}, "foo/**/bar", "foobar");
    doesTransform({PWT_REMOVE_COMMENTS}, "foo<!---->bar", "foobar");
}

TEST(TestTransforms, TestCoverage)
{
    auto rule = readFile("transform.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    /* // Want to hit a case where the transformer fail*/

    ddwaf_object map = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&map, "arg", ddwaf_object_stringl(&tmp, "\0", 1));

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &map, &ret, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "test_coverage"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = ".*",
                               .address = "arg",
                               .value = "",
                               .highlight = ""}}});

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransforms, TestUnicodeNormalization)
{
    int bla[128];
    for (uint32_t i = 1; i <= UTF8_MAX_CODEPOINT; ++i) {
        // We're assuming that no codepoint decomposes to more than 18 codepoints.
        // If one does so, you may need to update INFLIGHT_BUFFER_SIZE
        EXPECT_LE(ddwaf::utf8::normalize_codepoint(i, bla, 128), 18);
    }

    EXPECT_EQ(PWTransformer::getIDForString("unicode_normalize"), PWT_UNICODE_NORMALIZE);

    EXPECT_FALSE(shouldTransform({PWT_UNICODE_NORMALIZE}, "a"));
    EXPECT_FALSE(shouldTransform({PWT_UNICODE_NORMALIZE}, "`"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "ß"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "é"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "ı"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "–"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "—"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "⁵"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "⅖"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "ﬁ"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "𝑎"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "Å👨‍👩‍👧‍👦"));
    EXPECT_TRUE(shouldTransform({PWT_UNICODE_NORMALIZE}, "👨‍👩‍👧‍👦Å"));

    doesTransform({PWT_UNICODE_NORMALIZE}, "⃝", "");
    doesTransform({PWT_UNICODE_NORMALIZE}, "ß", "ss");
    doesTransform({PWT_UNICODE_NORMALIZE}, "é", "e");
    doesTransform({PWT_UNICODE_NORMALIZE}, "ı", "i");
    doesTransform({PWT_UNICODE_NORMALIZE}, "–", "-");
    doesTransform({PWT_UNICODE_NORMALIZE}, "—", "-");
    doesTransform({PWT_UNICODE_NORMALIZE}, "⁵", "5");
    doesTransform({PWT_UNICODE_NORMALIZE}, "⅖", "2/5");
    doesTransform({PWT_UNICODE_NORMALIZE}, "ﬁ", "fi");
    doesTransform({PWT_UNICODE_NORMALIZE}, "𝑎", "a");
    doesTransform(
        {PWT_UNICODE_NORMALIZE}, "Å👨‍👩‍👧‍👦", "A👨‍👩‍👧‍👦");
    doesTransform(
        {PWT_UNICODE_NORMALIZE}, "👨‍👩‍👧‍👦Å", "👨‍👩‍👧‍👦A");

    doesTransform({PWT_UNICODE_NORMALIZE}, "Aa𝑎éßıﬁ2⁵—⅖", "Aaaessifi25-2/5");
    doesTransform({PWT_UNICODE_NORMALIZE}, "Aẞé", "ASSe");
    doesTransform({PWT_UNICODE_NORMALIZE}, "Àße", "Asse");
    doesTransform({PWT_UNICODE_NORMALIZE}, "${${::-j}nd${upper:ı}:gopher//127.0.0.1:1389}",
        "${${::-j}nd${upper:i}:gopher//127.0.0.1:1389}");
}

TEST(TestTransforms, TestRuleRunOnKey)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("runOnKey.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    /* // Want to hit a case where the transformer fail*/

    ddwaf_object map = DDWAF_OBJECT_MAP, tmp = DDWAF_OBJECT_MAP, tmp2;
    ddwaf_object_map_add(&tmp, "rule1", ddwaf_object_string(&tmp2, "freefalling pony"));
    ddwaf_object_map_add(&map, "value", &tmp);

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &map, &ret, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "rule1",
                               .address = "value",
                               .path = {"rule1"},
                               .value = "rule1",
                               .highlight = "rule1"}}});

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
