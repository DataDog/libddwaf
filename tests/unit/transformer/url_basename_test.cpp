// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/url_basename.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestUrlBasename, NameAndID)
{
    EXPECT_STREQ(transformer::url_basename::name().data(), "url_basename");
    EXPECT_EQ(transformer::url_basename::id(), transformer_id::url_basename);
}

TEST(TestUrlBasename, EmptyString) { EXPECT_NO_TRANSFORM(url_basename, ""); }

TEST(TestUrlBasename, ValidTransform)
{
    EXPECT_TRANSFORM(url_basename, "index.php?a=b", "index.php");
    EXPECT_TRANSFORM(url_basename, "index.php#frag", "index.php");
    EXPECT_TRANSFORM(url_basename, "index.php?a=b#frag", "index.php");
    EXPECT_TRANSFORM(url_basename, "/path/index.php?a=b", "index.php");
    EXPECT_TRANSFORM(url_basename, "/path/index.php#frag", "index.php");
    EXPECT_TRANSFORM(url_basename, "/path/index.php?a=b#frag", "index.php");
    EXPECT_TRANSFORM(url_basename, "/path/index/?a=b", "");
    EXPECT_TRANSFORM(url_basename, "/path/index/#frag", "");
    EXPECT_TRANSFORM(url_basename, "/path/index/?a=b#frag", "");
    EXPECT_TRANSFORM(url_basename, "/?a=b", "");
    EXPECT_TRANSFORM(url_basename, "/#frag", "");
    EXPECT_TRANSFORM(url_basename, "/?a=b#frag", "");
    EXPECT_TRANSFORM(url_basename, "?a=b", "");
    EXPECT_TRANSFORM(url_basename, "#frag", "");
    EXPECT_TRANSFORM(url_basename, "?a=b#frag", "");
}

TEST(TestUrlBasename, InvalidTransform) { EXPECT_NO_TRANSFORM(url_basename, "index.php"); }

} // namespace
