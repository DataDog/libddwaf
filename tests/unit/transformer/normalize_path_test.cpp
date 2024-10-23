// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.hpp"
#include "transformer/normalize_path.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestNormalizePath, NameAndID)
{
    EXPECT_STREQ(transformer::normalize_path::name().data(), "normalize_path");
    EXPECT_EQ(transformer::normalize_path::id(), transformer_id::normalize_path);
}

TEST(TestNormalizePath, EmptyString) { EXPECT_NO_TRANSFORM(normalize_path, ""); }

TEST(TestNormalizePath, ValidTransform)
{
    EXPECT_TRANSFORM(normalize_path, "./file", "file");
    EXPECT_TRANSFORM(normalize_path, "./a/simple/path", "a/simple/path");
    EXPECT_TRANSFORM(normalize_path, "a/simple/./path", "a/simple/path");
    EXPECT_TRANSFORM(normalize_path, "./a/simple/wrong/../path", "a/simple/path");
    EXPECT_TRANSFORM(normalize_path, "a/simple/../../../../path", "/path");
    EXPECT_TRANSFORM(normalize_path, "a/simple/../../../../path.", "/path.");
}

TEST(TestNormalizePath, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(normalize_path, "/normal/path");
    EXPECT_NO_TRANSFORM(normalize_path, "/normal/path/to/dir/");
    EXPECT_NO_TRANSFORM(normalize_path, "path/to/somewhere");
    EXPECT_NO_TRANSFORM(normalize_path, "./");
    EXPECT_NO_TRANSFORM(normalize_path, "/");
    EXPECT_NO_TRANSFORM(normalize_path, "/path.");
}

TEST(TestNormalizePathWin, NameAndID)
{
    EXPECT_STREQ(transformer::normalize_path_win::name().data(), "normalize_path_win");
    EXPECT_EQ(transformer::normalize_path_win::id(), transformer_id::normalize_path_win);
}

TEST(TestNormalizePathWin, EmptyString) { EXPECT_NO_TRANSFORM(normalize_path_win, ""); }

TEST(TestNormalizePathWin, ValidTransform)
{
    EXPECT_TRANSFORM(normalize_path_win, R"(.\file)", "file");
    EXPECT_TRANSFORM(normalize_path_win, R"(.\a\simple\path)", "a/simple/path");
    EXPECT_TRANSFORM(normalize_path_win, R"(a\simple\.\path)", "a/simple/path");
    EXPECT_TRANSFORM(normalize_path_win, R"(.\a\simple\wrong\..\path)", "a/simple/path");
    EXPECT_TRANSFORM(normalize_path_win, R"(a\simple\..\..\..\..\path)", "/path");
    EXPECT_TRANSFORM(normalize_path_win, R"(a\simple\..\..\..\..\path.)", "/path.");
}

TEST(TestNormalizePathWin, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(normalize_path_win, "/normal/path");
    EXPECT_NO_TRANSFORM(normalize_path_win, "/normal/path/to/dir/");
    EXPECT_NO_TRANSFORM(normalize_path_win, "path/to/somewhere");
    EXPECT_NO_TRANSFORM(normalize_path_win, "./");
    EXPECT_NO_TRANSFORM(normalize_path_win, "/");
    EXPECT_NO_TRANSFORM(normalize_path_win, "/path.");
}

} // namespace
