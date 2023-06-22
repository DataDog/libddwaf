// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include <transformer/normalize_path.hpp>

TEST(TestNormalizePath, NameAndID)
{
    EXPECT_STREQ(transformer::normalize_path::name().data(), "normalize_path");
    EXPECT_EQ(transformer::normalize_path::id(), transformer_id::normalize_path);
}

TEST(TestNormalizePath, EmptyString)
{
    lazy_string str("");
    EXPECT_FALSE(transformer::normalize_path::transform(str));
    EXPECT_STREQ(str.data(), nullptr);
}

TEST(TestNormalizePath, ValidTransform)
{
    {
        lazy_string str("./file");
        EXPECT_TRUE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), "file");
    }

    {
        lazy_string str("./a/simple/path");
        EXPECT_TRUE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), "a/simple/path");
    }

    {
        lazy_string str("a/simple/./path");
        EXPECT_TRUE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), "a/simple/path");
    }

    {
        lazy_string str("./a/simple/wrong/../path");
        EXPECT_TRUE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), "a/simple/path");
    }

    {
        lazy_string str("a/simple/../../../../path");
        EXPECT_TRUE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), "/path");
    }
}

TEST(TestNormalizePath, InvalidTransform)
{
    {
        lazy_string str("/normal/path");
        EXPECT_FALSE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), nullptr);
    }

    {
        lazy_string str("/normal/path/to/dir/");
        EXPECT_FALSE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), nullptr);
    }

    {
        lazy_string str("path/to/somewhere");
        EXPECT_FALSE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), nullptr);
    }

    {
        lazy_string str("./");
        EXPECT_FALSE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), nullptr);
    }

    {
        lazy_string str("/");
        EXPECT_FALSE(transformer::normalize_path::transform(str));
        EXPECT_STREQ(str.data(), nullptr);
    }
}
