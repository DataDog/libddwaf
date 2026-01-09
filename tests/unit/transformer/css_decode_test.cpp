// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/css_decode.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {
TEST(TestCssDecode, NameAndID)
{
    EXPECT_STREQ(transformer::css_decode::name().data(), "css_decode");
    EXPECT_EQ(transformer::css_decode::id(), transformer_id::css_decode);
}

TEST(TestCssDecode, EmptyString) { EXPECT_NO_TRANSFORM(css_decode, ""); }

TEST(TestCssDecode, ValidTransform)
{
    EXPECT_TRANSFORM(css_decode, "\\00\\d800\\dfff\\110000 CSS transformations",
        "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD"
        "CSS transformations");
    EXPECT_TRANSFORM(
        css_decode, "CSS\\ff01  transformations\\e9", "CSS\xEF\xBC\x81 transformations\xC3\xA9");
    EXPECT_TRANSFORM(
        css_decode, "CSS\\77transformations\\14242", "CSSwtransformations\xF0\x94\x89\x82");
    EXPECT_TRANSFORM(css_decode, "CSS\\\n tran\\sformations", "CSS transformations");
    EXPECT_TRANSFORM(css_decode, "\\0SS\\0  transformations", "SS\xEF\xBF\xBD transformations");
}

TEST(TestCssDecode, InvalidTransform) { EXPECT_NO_TRANSFORM(css_decode, "no CSS transformations"); }

} // namespace
