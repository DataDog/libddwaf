// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/url_path.hpp"
#include "transformer_utils.hpp"

TEST(TestUrlPath, NameAndID)
{
    EXPECT_STREQ(transformer::url_path::name().data(), "url_path");
    EXPECT_EQ(transformer::url_path::id(), transformer_id::url_path);
}

TEST(TestUrlPath, EmptyString) { EXPECT_NO_TRANSFORM(url_path, ""); }

TEST(TestUrlPath, ValidTransform)
{
    EXPECT_TRANSFORM(url_path, "index.php?a=b", "index.php");
    EXPECT_TRANSFORM(url_path, "index.php#frag", "index.php");
    EXPECT_TRANSFORM(url_path, "index.php?a=b#frag", "index.php");
    EXPECT_TRANSFORM(url_path, "/path/index.php?a=b", "/path/index.php");
    EXPECT_TRANSFORM(url_path, "/path/index.php#frag", "/path/index.php");
    EXPECT_TRANSFORM(url_path, "/path/index.php?a=b#frag", "/path/index.php");
    EXPECT_TRANSFORM(url_path, "/path/index/?a=b", "/path/index/");
    EXPECT_TRANSFORM(url_path, "/path/index/#frag", "/path/index/");
    EXPECT_TRANSFORM(url_path, "/path/index/?a=b#frag", "/path/index/");
    EXPECT_TRANSFORM(url_path, "/?a=b", "/");
    EXPECT_TRANSFORM(url_path, "/#frag", "/");
    EXPECT_TRANSFORM(url_path, "/?a=b#frag", "/");
    EXPECT_TRANSFORM(url_path, "?a=b", "");
    EXPECT_TRANSFORM(url_path, "#frag", "");
    EXPECT_TRANSFORM(url_path, "?a=b#frag", "");
}

TEST(TestUrlPath, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(url_path, "index.php");
    EXPECT_NO_TRANSFORM(url_path, "/path/index.php");
    EXPECT_NO_TRANSFORM(url_path, "/path/to/index/");
}
