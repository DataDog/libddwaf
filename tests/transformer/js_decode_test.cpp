// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "transformer/js_decode.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;

namespace {
TEST(TestJsDecode, NameAndID)
{
    EXPECT_STREQ(transformer::js_decode::name().data(), "js_decode");
    EXPECT_EQ(transformer::js_decode::id(), transformer_id::js_decode);
}

TEST(TestJsDecode, EmptyString) { EXPECT_NO_TRANSFORM(js_decode, ""); }

TEST(TestJsDecode, ValidTransform)
{
    EXPECT_TRANSFORM(js_decode, "no JS\\x20transformations\\", "no JS transformations\\");
    EXPECT_TRANSFORM(js_decode, "no \\JS\\ttransformations", "no JS\ttransformations");
    EXPECT_TRANSFORM(js_decode, "\\a\\b\\c\\f\\n\\r\\t\\v\\z\\x\\u", "\a\bc\f\n\r\t\vz");
    EXPECT_TRANSFORM(js_decode, "\\x41\\x20\\x4aS\\x20transf\\x6Frmations", "A JS transformations");
    EXPECT_TRANSFORM(js_decode, "\\u0041 JS \\ud83e\\udd14 transformations\\uff01",
        "A JS \xf0\x9f\xa4\x94 transformations\xEF\xBC\x81");

    EXPECT_TRANSFORM(js_decode, "Test \\udbff\\udfff", "Test \xF4\x8F\xBF\xBF");
    EXPECT_TRANSFORM(js_decode, "Test\\x20\\", "Test \\");
    EXPECT_TRANSFORM(js_decode, "Test\\x20\\ ", "Test  ");
    EXPECT_TRANSFORM(js_decode, "Test\\x20\\x", "Test ");
    EXPECT_TRANSFORM(js_decode, "Test\\x20\\u", "Test ");
    EXPECT_TRANSFORM(js_decode, "Test\\x20\\ud801", "Test \xef\xbf\xbd");
}

TEST(TestJsDecode, InvalidTransform) { EXPECT_NO_TRANSFORM(js_decode, "no JS transformations"); }

} // namespace
