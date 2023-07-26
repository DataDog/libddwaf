// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/manager.hpp"

namespace {

// NOLINTNEXTLINE
#define EXPECT_TRANSFORM(src, dst, ...)                                                            \
  {                                                                                                \
    auto res = transform({src, sizeof(src) - 1}, {__VA_ARGS__});                                   \
    EXPECT_TRUE(res);                                                                              \
    if (res) {                                                                                     \
      EXPECT_STR(res.value(), dst);                                                                \
    }                                                                                              \
  }

// NOLINTNEXTLINE
#define EXPECT_NO_TRANSFORM(src, ...)                                                              \
  {                                                                                                \
    auto res = transform({src, sizeof(src) - 1}, {__VA_ARGS__});                                   \
    EXPECT_FALSE(res);                                                                             \
  }

std::optional<std::string> transform(std::string_view input, const std::vector<transformer_id> &ids)
{
    ddwaf_object src;
    ddwaf_object dst;
    ddwaf_object_stringl_nc(&src, input.data(), input.size());

    auto res = transformer::manager::transform(src, dst, ids);

    if (!res) {
        return std::nullopt;
    }

    std::string output{dst.stringValue, static_cast<std::size_t>(dst.nbEntries)};
    ddwaf_object_free(&dst);

    return {output};
}

} // namespace

TEST(TestTransformerManager, ValidSingleTransforms)
{
    EXPECT_TRANSFORM("  wh  ite  ", " wh ite ", transformer_id::compress_whitespace);
    EXPECT_TRANSFORM("LoWeRCase", "lowercase", transformer_id::lowercase);
    EXPECT_TRANSFORM("./file", "file", transformer_id::normalize_path);
    EXPECT_TRANSFORM(".\\file", "file", transformer_id::normalize_path_win);
    EXPECT_TRANSFORM("#", "", transformer_id::remove_comments);
    EXPECT_TRANSFORM("\0r", "r", transformer_id::remove_nulls);
    EXPECT_TRANSFORM("é", "e", transformer_id::unicode_normalize);
    EXPECT_TRANSFORM("%41", "A", transformer_id::url_decode);
    EXPECT_TRANSFORM("%%341", "A", transformer_id::url_decode_iis);
}

TEST(TestTransformerManager, InvalidSingleTransforms)
{
    EXPECT_NO_TRANSFORM(" wh ite ", transformer_id::compress_whitespace);
    EXPECT_NO_TRANSFORM("lowercase", transformer_id::lowercase);
    EXPECT_NO_TRANSFORM("file", transformer_id::normalize_path);
    EXPECT_NO_TRANSFORM("file", transformer_id::normalize_path_win);
    EXPECT_NO_TRANSFORM("*", transformer_id::remove_comments);
    EXPECT_NO_TRANSFORM("r", transformer_id::remove_nulls);
    EXPECT_NO_TRANSFORM("e", transformer_id::unicode_normalize);
    EXPECT_NO_TRANSFORM("A", transformer_id::url_decode);
    EXPECT_NO_TRANSFORM("A", transformer_id::url_decode_iis);
}

TEST(TestTransformerManager, ValidMultipleTransforms)
{
    EXPECT_TRANSFORM(
        "  WhitE  ", " white ", transformer_id::compress_whitespace, transformer_id::lowercase);

    EXPECT_TRANSFORM("  WhitE  # hello", " white ", transformer_id::compress_whitespace,
        transformer_id::lowercase, transformer_id::remove_comments);

    EXPECT_TRANSFORM("  Wh\0itE  # hello", " white ", transformer_id::compress_whitespace,
        transformer_id::lowercase, transformer_id::remove_comments, transformer_id::remove_nulls);

    EXPECT_TRANSFORM("  Wh\0iTé  # hello", " white ", transformer_id::compress_whitespace,
        transformer_id::lowercase, transformer_id::remove_comments, transformer_id::remove_nulls,
        transformer_id::unicode_normalize);

    EXPECT_TRANSFORM("  Wh\0iTé  # hello", " white ", transformer_id::remove_nulls,
        transformer_id::unicode_normalize, transformer_id::remove_comments,
        transformer_id::lowercase, transformer_id::compress_whitespace);
}

TEST(TestTransformerManager, InvalidMultipleTransforms)
{
    EXPECT_NO_TRANSFORM(" white ", transformer_id::compress_whitespace, transformer_id::lowercase);

    EXPECT_NO_TRANSFORM(" white ", transformer_id::compress_whitespace, transformer_id::lowercase,
        transformer_id::remove_comments);

    EXPECT_NO_TRANSFORM(" white ", transformer_id::compress_whitespace, transformer_id::lowercase,
        transformer_id::remove_comments, transformer_id::remove_nulls);

    EXPECT_NO_TRANSFORM(" white ", transformer_id::compress_whitespace, transformer_id::lowercase,
        transformer_id::remove_comments, transformer_id::remove_nulls,
        transformer_id::unicode_normalize);

    EXPECT_NO_TRANSFORM(" white ", transformer_id::remove_nulls, transformer_id::unicode_normalize,
        transformer_id::remove_comments, transformer_id::lowercase,
        transformer_id::compress_whitespace);
}
