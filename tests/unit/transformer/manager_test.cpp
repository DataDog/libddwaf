// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/base.hpp"
#include "transformer/manager.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

// NOLINTNEXTLINE
#define EXPECT_TRANSFORM(src, dst, ...)                                                            \
    {                                                                                              \
        auto res = transform({src, sizeof(src) - 1}, {__VA_ARGS__});                               \
        EXPECT_TRUE(res);                                                                          \
        if (res) {                                                                                 \
            EXPECT_STR(res.value(), dst);                                                          \
        }                                                                                          \
    }

// NOLINTNEXTLINE
#define EXPECT_NO_TRANSFORM(src, ...)                                                              \
    {                                                                                              \
        auto res = transform({src, sizeof(src) - 1}, {__VA_ARGS__});                               \
        EXPECT_FALSE(res);                                                                         \
    }

std::optional<std::string> transform(std::string_view input, const std::vector<transformer_id> &ids)
{
    auto src = owned_object::make_string_nocopy(input, nullptr);
    owned_object dst;

    auto res = transformer::manager::transform(src, dst, ids);

    if (!res) {
        return std::nullopt;
    }

    return {object_view{dst}.as<std::string>()};
}

TEST(TestTransformerManager, InvalidTypes)
{
    owned_object src(29U);
    owned_object dst;

    {
        std::vector<transformer_id> ids{transformer_id::compress_whitespace};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::lowercase};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::normalize_path};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::normalize_path_win};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::remove_comments};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::remove_nulls};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::unicode_normalize};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::url_decode};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::url_decode_iis};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::base64_decode};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::base64_encode};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::url_path};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::url_basename};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::url_querystring};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::shell_unescape};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::js_decode};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::html_entity_decode};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
    {
        std::vector<transformer_id> ids{transformer_id::css_decode};
        EXPECT_FALSE(transformer::manager::transform(src, dst, ids));
    }
}

TEST(TestTransformerManager, EmptyStrings)
{
    EXPECT_NO_TRANSFORM("", transformer_id::compress_whitespace);
    EXPECT_NO_TRANSFORM("", transformer_id::lowercase);
    EXPECT_NO_TRANSFORM("", transformer_id::normalize_path);
    EXPECT_NO_TRANSFORM("", transformer_id::normalize_path_win);
    EXPECT_NO_TRANSFORM("", transformer_id::remove_comments);
    EXPECT_NO_TRANSFORM("", transformer_id::remove_nulls);
    EXPECT_NO_TRANSFORM("", transformer_id::unicode_normalize);
    EXPECT_NO_TRANSFORM("", transformer_id::url_decode);
    EXPECT_NO_TRANSFORM("", transformer_id::url_decode_iis);
    EXPECT_NO_TRANSFORM("", transformer_id::base64_decode);
    EXPECT_NO_TRANSFORM("", transformer_id::base64_encode);
    EXPECT_NO_TRANSFORM("", transformer_id::url_path);
    EXPECT_NO_TRANSFORM("", transformer_id::url_basename);
    EXPECT_NO_TRANSFORM("", transformer_id::url_querystring);
    EXPECT_NO_TRANSFORM("", transformer_id::shell_unescape);
    EXPECT_NO_TRANSFORM("", transformer_id::js_decode);
    EXPECT_NO_TRANSFORM("", transformer_id::html_entity_decode);
    EXPECT_NO_TRANSFORM("", transformer_id::css_decode);
}

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
    EXPECT_TRANSFORM("Zm9vYmF", "fooba@", transformer_id::base64_decode);
    EXPECT_TRANSFORM("fooba@", "Zm9vYmFA", transformer_id::base64_encode);
    EXPECT_TRANSFORM("/querystring/index/?a=b#frag", "a=b", transformer_id::url_querystring);
    EXPECT_TRANSFORM("/path/index/?a=b", "/path/index/", transformer_id::url_path);
    EXPECT_TRANSFORM("/path/index.php#frag", "index.php", transformer_id::url_basename);
    EXPECT_TRANSFORM("n^ormal\\ sent\"enc'e", "normal sentence", transformer_id::shell_unescape);
    EXPECT_TRANSFORM("Test\\x20\\ud801", "Test \xef\xbf\xbd", transformer_id::js_decode);
    EXPECT_TRANSFORM("&#x41;", "A", transformer_id::html_entity_decode);
    EXPECT_TRANSFORM("\\0SS\\0  transform", "SS\xEF\xBF\xBD transform", transformer_id::css_decode);
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
    EXPECT_NO_TRANSFORM("normal sentence", transformer_id::base64_decode);
    EXPECT_NO_TRANSFORM("/path/to/index/", transformer_id::url_path);
    EXPECT_NO_TRANSFORM("index.php", transformer_id::url_basename);
    EXPECT_NO_TRANSFORM("normal sentence(really)", transformer_id::shell_unescape);
    EXPECT_NO_TRANSFORM("no JS transformations", transformer_id::js_decode);
    EXPECT_NO_TRANSFORM("no &ampblaHTML transformations", transformer_id::html_entity_decode);
    EXPECT_NO_TRANSFORM("no CSS transformations", transformer_id::css_decode);
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

    EXPECT_TRANSFORM("  Wh\0iTé  # hello", " white ", transformer_id::remove_nulls,
        transformer_id::unicode_normalize, transformer_id::remove_comments,
        transformer_id::lowercase, transformer_id::compress_whitespace,
        transformer_id::base64_encode, transformer_id::base64_decode);

    EXPECT_TRANSFORM("CSS\\%0a tran\\sformations", "CSS transformations",
        transformer_id::url_decode, transformer_id::css_decode);
    EXPECT_TRANSFORM("CSS transformations\\", "CSS transformations", transformer_id::url_decode,
        transformer_id::css_decode);
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

    EXPECT_NO_TRANSFORM(" white ", transformer_id::remove_nulls, transformer_id::unicode_normalize,
        transformer_id::remove_comments, transformer_id::lowercase, transformer_id::base64_decode,
        transformer_id::compress_whitespace);
}

} // namespace
