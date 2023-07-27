// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/html_entity_decode.hpp"
#include "transformer_utils.hpp"

TEST(TestHtmlEntityDecode, NameAndID)
{
    EXPECT_STREQ(transformer::html_entity_decode::name().data(), "html_entity_decode");
    EXPECT_EQ(transformer::html_entity_decode::id(), transformer_id::html_entity_decode);
}

TEST(TestHtmlEntityDecode, EmptyString) { EXPECT_NO_TRANSFORM(html_entity_decode, ""); }

TEST(TestHtmlEntityDecode, ValidTransform)
{
    EXPECT_TRANSFORM(html_entity_decode,
        "HTML &#x0000000000000000000000000000041 &#x41; transformation", "HTML A A transformation");
    EXPECT_TRANSFORM(html_entity_decode,
        "HTML &#0000000000000000000000000000065 &#65; transformation", "HTML A A transformation");

    EXPECT_TRANSFORM(html_entity_decode, "&lt;&gt;&amp;&quot;&nbsp;", "<>&\"\xa0");
    EXPECT_TRANSFORM(html_entity_decode, "&#x41 :) &#x &#X &# &#xffffffff &#999999999 &lt",
        "A :) &#x &#X &# \xEF\xBF\xBD \xEF\xBF\xBD &lt");

    EXPECT_TRANSFORM(html_entity_decode, "&#x41;", "A");
    EXPECT_TRANSFORM(html_entity_decode, "&#x41", "A");
    EXPECT_TRANSFORM(html_entity_decode, "&#65;", "A");
    EXPECT_TRANSFORM(html_entity_decode, "&#65", "A");
    EXPECT_TRANSFORM(html_entity_decode, "&lt;", "<");

    EXPECT_TRANSFORM(html_entity_decode, "HTML &#xffffff fffff &#x41; transformation",
        "HTML \xef\xbf\xbd fffff A transformation");
    EXPECT_TRANSFORM(html_entity_decode, "HTML &#xffffffffff9fff fffff &#x41; transformation",
        "HTML \xef\xbf\xbd fffff A transformation");
    EXPECT_TRANSFORM(html_entity_decode, "HTML &#9999999 99999 &#x41; transformation",
        "HTML \xef\xbf\xbd 99999 A transformation");
    EXPECT_TRANSFORM(html_entity_decode, "HTML &#9999999ffff 99999 &#x41; transformation",
        "HTML \xef\xbf\xbd"
        "ffff 99999 A transformation");
}

TEST(TestHtmlEntityDecode, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(html_entity_decode, "no HTML transformations");
    EXPECT_NO_TRANSFORM(html_entity_decode, "no HTML &&transformations");
    EXPECT_NO_TRANSFORM(html_entity_decode, "no &ampblaHTML transformations");
    EXPECT_NO_TRANSFORM(html_entity_decode, "no &#HTML transformations");
    EXPECT_NO_TRANSFORM(html_entity_decode, "no");
}
