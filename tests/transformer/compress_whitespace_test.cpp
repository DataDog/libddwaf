// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "transformer/compress_whitespace.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestCompressWhitespace, NameAndID)
{
    EXPECT_STREQ(transformer::compress_whitespace::name().data(), "compress_whitespace");
    EXPECT_EQ(transformer::compress_whitespace::id(), transformer_id::compress_whitespace);
}

TEST(TestCompressWhitespace, EmptyString) { EXPECT_NO_TRANSFORM(compress_whitespace, ""); }

TEST(TestCompressWhitespace, ValidTransform)
{
    EXPECT_TRANSFORM(compress_whitespace, "  c", " c");
    EXPECT_TRANSFORM(compress_whitespace, "c  w", "c w");
    EXPECT_TRANSFORM(compress_whitespace, "c  ", "c ");
    EXPECT_TRANSFORM(compress_whitespace, "  c  ", " c ");
    EXPECT_TRANSFORM(compress_whitespace, "        c", " c");
    EXPECT_TRANSFORM(compress_whitespace, "c      w", "c w");
    EXPECT_TRANSFORM(compress_whitespace, "c      ", "c ");
    EXPECT_TRANSFORM(compress_whitespace, "      c     ", " c ");
    EXPECT_TRANSFORM(compress_whitespace, "      compress  white     space transformer     ",
        " compress white space transformer ");
}

TEST(TestCompressWhitespace, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(compress_whitespace, "c");
    EXPECT_NO_TRANSFORM(compress_whitespace, " c");
    EXPECT_NO_TRANSFORM(compress_whitespace, "c ");
    EXPECT_NO_TRANSFORM(compress_whitespace, " c ");
    EXPECT_NO_TRANSFORM(compress_whitespace, "c w");
    EXPECT_NO_TRANSFORM(compress_whitespace, "compress_whitespace");
    EXPECT_NO_TRANSFORM(compress_whitespace, "compress_whitespace but it doesn't matter");
}

} // namespace
