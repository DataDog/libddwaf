// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parser/common.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::parser;

// NOLINTBEGIN(cppcoreguidelines-macro-usage,bugprone-unchecked-optional-access)
#define EXPECT_OPTEQ(opt, expected)                                                                \
    ASSERT_TRUE((opt));                                                                            \
    EXPECT_EQ((opt), expected);
// NOLINTEND(cppcoreguidelines-macro-usage,bugprone-unchecked-optional-access)

namespace {

TEST(TestParserTransformers, ValidTransformers)
{
    EXPECT_OPTEQ(transformer_from_string("lowercase"), transformer_id::lowercase);
    EXPECT_OPTEQ(transformer_from_string("remove_nulls"), transformer_id::remove_nulls);
    EXPECT_OPTEQ(
        transformer_from_string("compress_whitespace"), transformer_id::compress_whitespace);
    EXPECT_OPTEQ(transformer_from_string("normalize_path"), transformer_id::normalize_path);
    EXPECT_OPTEQ(transformer_from_string("normalize_path_win"), transformer_id::normalize_path_win);
    EXPECT_OPTEQ(transformer_from_string("url_decode"), transformer_id::url_decode);
    EXPECT_OPTEQ(transformer_from_string("url_decode_iis"), transformer_id::url_decode_iis);
    EXPECT_OPTEQ(transformer_from_string("css_decode"), transformer_id::css_decode);
    EXPECT_OPTEQ(transformer_from_string("js_decode"), transformer_id::js_decode);
    EXPECT_OPTEQ(transformer_from_string("html_entity_decode"), transformer_id::html_entity_decode);
    EXPECT_OPTEQ(transformer_from_string("base64_decode"), transformer_id::base64_decode);
    EXPECT_OPTEQ(transformer_from_string("base64_encode"), transformer_id::base64_encode);
    EXPECT_OPTEQ(transformer_from_string("shell_unescape"), transformer_id::shell_unescape);
    EXPECT_OPTEQ(transformer_from_string("url_basename"), transformer_id::url_basename);
    EXPECT_OPTEQ(transformer_from_string("url_path"), transformer_id::url_path);
    EXPECT_OPTEQ(transformer_from_string("url_querystring"), transformer_id::url_querystring);
    EXPECT_OPTEQ(transformer_from_string("remove_comments"), transformer_id::remove_comments);
    EXPECT_OPTEQ(transformer_from_string("unicode_normalize"), transformer_id::unicode_normalize);
}

TEST(TestParserTransformers, AlisedTransformers)
{
    EXPECT_OPTEQ(transformer_from_string("removeNulls"), transformer_id::remove_nulls);
    EXPECT_OPTEQ(
        transformer_from_string("compressWhiteSpace"), transformer_id::compress_whitespace);
    EXPECT_OPTEQ(transformer_from_string("normalizePath"), transformer_id::normalize_path);
    EXPECT_OPTEQ(transformer_from_string("normalizePathWin"), transformer_id::normalize_path_win);
    EXPECT_OPTEQ(transformer_from_string("urlDecode"), transformer_id::url_decode);
    EXPECT_OPTEQ(transformer_from_string("urlDecodeUni"), transformer_id::url_decode_iis);
    EXPECT_OPTEQ(transformer_from_string("cssDecode"), transformer_id::css_decode);
    EXPECT_OPTEQ(transformer_from_string("jsDecode"), transformer_id::js_decode);
    EXPECT_OPTEQ(transformer_from_string("htmlEntityDecode"), transformer_id::html_entity_decode);
    EXPECT_OPTEQ(transformer_from_string("base64Decode"), transformer_id::base64_decode);
    EXPECT_OPTEQ(transformer_from_string("base64Encode"), transformer_id::base64_encode);
    EXPECT_OPTEQ(transformer_from_string("cmdLine"), transformer_id::shell_unescape);
    EXPECT_OPTEQ(transformer_from_string("_sqr_basename"), transformer_id::url_basename);
    EXPECT_OPTEQ(transformer_from_string("_sqr_filename"), transformer_id::url_path);
    EXPECT_OPTEQ(transformer_from_string("_sqr_querystring"), transformer_id::url_querystring);
    EXPECT_OPTEQ(transformer_from_string("removeComments"), transformer_id::remove_comments);
}

TEST(TestParserTransformers, InvalidTransformers)
{
    EXPECT_FALSE(transformer_from_string("LoWeRcAse"));
    EXPECT_FALSE(transformer_from_string("raAndom"));
}

} // namespace
