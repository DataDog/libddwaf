// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/transformers/";

TEST(TestTransformers, Base64Decode)
{
    auto rule = read_file<ddwaf_object>("base64_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "J09SIDE9MS8q");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "is_sqli",
                               .highlight = "s&1c"sv,
                               .args = {{.value = "'OR 1=1/*"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64DecodeAlias)
{
    auto rule = read_file<ddwaf_object>("base64_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "J09SIDE9MS8q");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "is_sqli",
                               .highlight = "s&1c"sv,
                               .args = {{.value = "'OR 1=1/*"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64UrlDecode)
{
    auto rule = read_file<ddwaf_object>("base64url_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "J09SIDE9MS8q");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "is_sqli",
                               .highlight = "s&1c"sv,
                               .args = {{.value = "'OR 1=1/*"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64Encode)
{
    auto rule = read_file<ddwaf_object>("base64_encode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "'OR 1=1/*");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "J09SIDE9MS8q",
                               .highlight = "J09SIDE9MS8q"sv,
                               .args = {{.value = "J09SIDE9MS8q"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64EncodeAlias)
{
    auto rule = read_file<ddwaf_object>("base64_encode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "'OR 1=1/*");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "J09SIDE9MS8q",
                               .highlight = "J09SIDE9MS8q"sv,
                               .args = {{.value = "J09SIDE9MS8q"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CompressWhitespace)
{
    auto rule = read_file<ddwaf_object>("compress_whitespace.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "attack      value");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "attack value",
                               .highlight = "attack value"sv,
                               .args = {{.value = "attack value"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CompressWhitespaceAlias)
{
    auto rule = read_file<ddwaf_object>("compress_whitespace.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "attack      value");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "attack value",
                               .highlight = "attack value"sv,
                               .args = {{.value = "attack value"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CssDecode)
{
    auto rule = read_file<ddwaf_object>("css_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "CSS\\\n tran\\sformations");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(
        out, {.id = "1",
                 .name = "rule1",
                 .tags = {{"type", "flow1"}, {"category", "category1"}},
                 .matches = {{.op = "match_regex",
                     .op_value = "CSS transformations",
                     .highlight = "CSS transformations"sv,
                     .args = {{.value = "CSS transformations"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CssDecodeAlias)
{
    auto rule = read_file<ddwaf_object>("css_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "CSS\\\n tran\\sformations");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(
        out, {.id = "2",
                 .name = "rule2",
                 .tags = {{"type", "flow1"}, {"category", "category1"}},
                 .matches = {{.op = "match_regex",
                     .op_value = "CSS transformations",
                     .highlight = "CSS transformations"sv,
                     .args = {{.value = "CSS transformations"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, HtmlEntityDecode)
{
    auto rule = read_file<ddwaf_object>("html_entity_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "HTML &#x0000000000000000000000000000041 &#x41; transformation");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(
        out, {.id = "1",
                 .name = "rule1",
                 .tags = {{"type", "flow1"}, {"category", "category1"}},
                 .matches = {{.op = "match_regex",
                     .op_value = "HTML A A transformation",
                     .highlight = "HTML A A transformation"sv,
                     .args = {{.value = "HTML A A transformation"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, HtmlEntityDecodeAlias)
{
    auto rule = read_file<ddwaf_object>("html_entity_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "HTML &#x0000000000000000000000000000041 &#x41; transformation");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(
        out, {.id = "2",
                 .name = "rule2",
                 .tags = {{"type", "flow1"}, {"category", "category1"}},
                 .matches = {{.op = "match_regex",
                     .op_value = "HTML A A transformation",
                     .highlight = "HTML A A transformation"sv,
                     .args = {{.value = "HTML A A transformation"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, JsDecode)
{
    auto rule = read_file<ddwaf_object>("js_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, R"(\x41\x20\x4aS\x20transf\x6Frmation)");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(
        out, {.id = "1",
                 .name = "rule1",
                 .tags = {{"type", "flow1"}, {"category", "category1"}},
                 .matches = {{.op = "match_regex",
                     .op_value = "A JS transformation",
                     .highlight = "A JS transformation"sv,
                     .args = {{.value = "A JS transformation"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, JsDecodeAlias)
{
    auto rule = read_file<ddwaf_object>("js_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, R"(\x41\x20\x4aS\x20transf\x6Frmation)");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(
        out, {.id = "2",
                 .name = "rule2",
                 .tags = {{"type", "flow1"}, {"category", "category1"}},
                 .matches = {{.op = "match_regex",
                     .op_value = "A JS transformation",
                     .highlight = "A JS transformation"sv,
                     .args = {{.value = "A JS transformation"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Lowercase)
{
    auto rule = read_file<ddwaf_object>("lowercase.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "ArAcHnI");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "arachni",
                               .highlight = "arachni"sv,
                               .args = {{.value = "arachni"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, NormalizePath)
{
    auto rule = read_file<ddwaf_object>("normalize_path.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/etc/dir1/dir2/../../passwd");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, NormalizePathAlias)
{
    auto rule = read_file<ddwaf_object>("normalize_path.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/etc/dir1/dir2/../../passwd");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, NormalizePathWin)
{
    auto rule = read_file<ddwaf_object>("normalize_path_win.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, R"(\etc\dir1\dir2\..\..\passwd)");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, NormalizePathAliasWin)
{
    auto rule = read_file<ddwaf_object>("normalize_path_win.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, R"(\etc\dir1\dir2\..\..\passwd)");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, RemoveComments)
{
    auto rule = read_file<ddwaf_object>("remove_comments.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "passwd#asdsd");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "passwd",
                               .highlight = "passwd"sv,
                               .args = {{.value = "passwd"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, RemoveCommentsAlias)
{
    auto rule = read_file<ddwaf_object>("remove_comments.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "passwd#asdsd");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "passwd",
                               .highlight = "passwd"sv,
                               .args = {{.value = "passwd"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, RemoveNulls)
{
    auto rule = read_file<ddwaf_object>("remove_nulls.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_stringl(&string, "/etc/\0passwd", sizeof("/etc/\0passwd") - 1);
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, RemoveNullsAlias)
{
    auto rule = read_file<ddwaf_object>("remove_nulls.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_stringl(&string, "/etc/\0passwd", sizeof("/etc/\0passwd") - 1);
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, ShellUnescape)
{
    auto rule = read_file<ddwaf_object>("shell_unescape.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/\\etc/\"pass^wd");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, ShellUnescapeAlias)
{
    auto rule = read_file<ddwaf_object>("shell_unescape.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/\\etc/\"pass^wd");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UnicodeNormalize)
{
    auto rule = read_file<ddwaf_object>("unicode_normalize.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/étc/p𝑎ßwd");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlBasename)
{
    auto rule = read_file<ddwaf_object>("url_basename.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/path/to/index.php?a=b#frag");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "index.php",
                               .highlight = "index.php"sv,
                               .args = {{.value = "index.php"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlBasenameAlias)
{
    auto rule = read_file<ddwaf_object>("url_basename.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/path/to/index.php?a=b#frag");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "index.php",
                               .highlight = "index.php"sv,
                               .args = {{.value = "index.php"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlDecode)
{
    auto rule = read_file<ddwaf_object>("url_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "%61n+%61ttack%20valu%65");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "an attack value",
                               .highlight = "an attack value"sv,
                               .args = {{.value = "an attack value"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlDecodeAlias)
{
    auto rule = read_file<ddwaf_object>("url_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "%61n+%61ttack%20valu%65");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "an attack value",
                               .highlight = "an attack value"sv,
                               .args = {{.value = "an attack value"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlDecodeIis)
{
    auto rule = read_file<ddwaf_object>("url_decode_iis.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "%61n+%61ttack%20valu%65");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "an attack value",
                               .highlight = "an attack value"sv,
                               .args = {{.value = "an attack value"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlDecodeIisAlias)
{
    auto rule = read_file<ddwaf_object>("url_decode_iis.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "%61n+%61ttack%20valu%65");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "an attack value",
                               .highlight = "an attack value"sv,
                               .args = {{.value = "an attack value"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlPath)
{
    auto rule = read_file<ddwaf_object>("url_path.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/path/to/index.php?a=b#frag");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/path/to/index.php",
                               .highlight = "/path/to/index.php"sv,
                               .args = {{.value = "/path/to/index.php"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlPathAlias)
{
    auto rule = read_file<ddwaf_object>("url_path.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/path/to/index.php?a=b#frag");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/path/to/index.php",
                               .highlight = "/path/to/index.php"sv,
                               .args = {{.value = "/path/to/index.php"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlQuerystring)
{
    auto rule = read_file<ddwaf_object>("url_querystring.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/path/to/index.php?a=b#frag");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "a=b",
                               .highlight = "a=b"sv,
                               .args = {{.value = "a=b"sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlQuerystringAlias)
{
    auto rule = read_file<ddwaf_object>("url_querystring.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "/path/to/index.php?a=b#frag");
    ddwaf_object_map_add(&map, "value2", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "a=b",
                               .highlight = "a=b"sv,
                               .args = {{.value = "a=b"sv, .address = "value2"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Mixed)
{
    auto rule = read_file<ddwaf_object>("mixed.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object string;
    ddwaf_object_string(&string, "L3AgIGEgIHRIL3QgIE8vRmlsRS5QSFA/YT1iI2ZyYWc=");
    ddwaf_object_map_add(&map, "value1", &string);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(
        out, {.id = "1",
                 .name = "rule1",
                 .tags = {{"type", "flow1"}, {"category", "category1"}},
                 .matches = {{.op = "match_regex",
                     .op_value = "L3AgYSB0aC90IG8vZmlsZS5waHA=",
                     .highlight = "L3AgYSB0aC90IG8vZmlsZS5waHA="sv,
                     .args = {{.value = "L3AgYSB0aC90IG8vZmlsZS5waHA="sv, .address = "value1"}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
