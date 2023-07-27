// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/url_querystring.hpp"
#include "transformer_utils.hpp"

TEST(TestUrlQuerystring, NameAndID)
{
    EXPECT_STREQ(transformer::url_querystring::name().data(), "url_querystring");
    EXPECT_EQ(transformer::url_querystring::id(), transformer_id::url_querystring);
}

TEST(TestUrlQuerystring, EmptyString) { EXPECT_NO_TRANSFORM(url_querystring, ""); }

TEST(TestUrlQuerystring, ValidTransform)
{
    EXPECT_TRANSFORM(url_querystring, "index.php?a=b", "a=b");
    EXPECT_TRANSFORM(url_querystring, "index.php?a=b&c=d&e=f", "a=b&c=d&e=f");
    EXPECT_TRANSFORM(url_querystring, "index.php#frag", "");
    EXPECT_TRANSFORM(url_querystring, "index.php?a=b#frag", "a=b");
    EXPECT_TRANSFORM(url_querystring, "/querystring/index.php?a=b", "a=b");
    EXPECT_TRANSFORM(url_querystring, "/querystring/index.php#frag", "");
    EXPECT_TRANSFORM(url_querystring, "/querystring/index.php?a=b#frag", "a=b");
    EXPECT_TRANSFORM(url_querystring, "/querystring/index/?a=b", "a=b");
    EXPECT_TRANSFORM(url_querystring, "/querystring/index/#frag", "");
    EXPECT_TRANSFORM(url_querystring, "/querystring/index/?a=b#frag", "a=b");
    EXPECT_TRANSFORM(url_querystring, "/?a=b", "a=b");
    EXPECT_TRANSFORM(url_querystring, "/#frag", "");
    EXPECT_TRANSFORM(url_querystring, "/?a=b#frag", "a=b");
    EXPECT_TRANSFORM(url_querystring, "?a=b", "a=b");
    EXPECT_TRANSFORM(url_querystring, R"(?a=b&c="?sndj")", R"(a=b&c="?sndj")");
    EXPECT_TRANSFORM(url_querystring, "#frag", "");
    EXPECT_TRANSFORM(url_querystring, "?a=b#frag", "a=b");
}

TEST(TestUrlQuerystring, InvalidTransform)
{
    // This transformer has no invalid cases:
    //   - If the query string isn't available, the result should be an empty string
    //   - If the entire string is a querystring, the question mark has to be removed
}
