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
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("base64_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("J09SIDE9MS8q"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "is_sqli",
                               .highlight = "s&1c"sv,
                               .args = {{.value = "'OR 1=1/*"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64DecodeAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("base64_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("J09SIDE9MS8q"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "is_sqli",
                               .highlight = "s&1c"sv,
                               .args = {{.value = "'OR 1=1/*"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64UrlDecode)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("base64url_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("J09SIDE9MS8q"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "is_sqli",
                               .highlight = "s&1c"sv,
                               .args = {{.value = "'OR 1=1/*"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64Encode)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("base64_encode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("'OR 1=1/*"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "J09SIDE9MS8q",
                               .highlight = "J09SIDE9MS8q"sv,
                               .args = {{.value = "J09SIDE9MS8q"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64EncodeAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("base64_encode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("'OR 1=1/*"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "J09SIDE9MS8q",
                               .highlight = "J09SIDE9MS8q"sv,
                               .args = {{.value = "J09SIDE9MS8q"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CompressWhitespace)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("compress_whitespace.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("attack      value"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "attack value",
                               .highlight = "attack value"sv,
                               .args = {{.value = "attack value"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CompressWhitespaceAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("compress_whitespace.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("attack      value"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "attack value",
                               .highlight = "attack value"sv,
                               .args = {{.value = "attack value"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CssDecode)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("css_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("CSS\\\n tran\\sformations"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
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

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CssDecodeAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("css_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("CSS\\\n tran\\sformations"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
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

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, HtmlEntityDecode)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("html_entity_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert_key(&map, STRL("value1"), alloc),
        STRL("HTML &#x0000000000000000000000000000041 &#x41; transformation"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
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

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, HtmlEntityDecodeAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("html_entity_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert_key(&map, STRL("value2"), alloc),
        STRL("HTML &#x0000000000000000000000000000041 &#x41; transformation"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
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

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, JsDecode)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("js_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert_key(&map, STRL("value1"), alloc),
        STRL(R"(\x41\x20\x4aS\x20transf\x6Frmation)"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
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

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, JsDecodeAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("js_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert_key(&map, STRL("value2"), alloc),
        STRL(R"(\x41\x20\x4aS\x20transf\x6Frmation)"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
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

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Lowercase)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("lowercase.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("ArAcHnI"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "arachni",
                               .highlight = "arachni"sv,
                               .args = {{.value = "arachni"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, NormalizePath)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("normalize_path.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("/etc/dir1/dir2/../../passwd"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, NormalizePathAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("normalize_path.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("/etc/dir1/dir2/../../passwd"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, NormalizePathWin)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("normalize_path_win.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert_key(&map, STRL("value1"), alloc),
        STRL(R"(\etc\dir1\dir2\..\..\passwd)"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, NormalizePathAliasWin)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("normalize_path_win.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert_key(&map, STRL("value2"), alloc),
        STRL(R"(\etc\dir1\dir2\..\..\passwd)"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, RemoveComments)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("remove_comments.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("passwd#asdsd"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "passwd",
                               .highlight = "passwd"sv,
                               .args = {{.value = "passwd"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, RemoveCommentsAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("remove_comments.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("passwd#asdsd"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "passwd",
                               .highlight = "passwd"sv,
                               .args = {{.value = "passwd"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, RemoveNulls)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("remove_nulls.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("/etc/\0passwd"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, RemoveNullsAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("remove_nulls.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert_key(&map, STRL("value2"), alloc),
        "/etc/\0passwd", sizeof("/etc/\0passwd") - 1);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, ShellUnescape)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("shell_unescape.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("/\\etc/\"pass^wd"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, ShellUnescapeAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("shell_unescape.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("/\\etc/\"pass^wd"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UnicodeNormalize)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("unicode_normalize.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("/étc/p𝑎ßwd"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/etc/passwd",
                               .highlight = "/etc/passwd"sv,
                               .args = {{.value = "/etc/passwd"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlBasename)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_basename.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("/path/to/index.php?a=b#frag"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "index.php",
                               .highlight = "index.php"sv,
                               .args = {{.value = "index.php"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlBasenameAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_basename.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("/path/to/index.php?a=b#frag"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "index.php",
                               .highlight = "index.php"sv,
                               .args = {{.value = "index.php"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlDecode)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("%61n+%61ttack%20valu%65"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "an attack value",
                               .highlight = "an attack value"sv,
                               .args = {{.value = "an attack value"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlDecodeAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_decode.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("%61n+%61ttack%20valu%65"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "an attack value",
                               .highlight = "an attack value"sv,
                               .args = {{.value = "an attack value"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlDecodeIis)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_decode_iis.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("%61n+%61ttack%20valu%65"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "an attack value",
                               .highlight = "an attack value"sv,
                               .args = {{.value = "an attack value"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlDecodeIisAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_decode_iis.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("%61n+%61ttack%20valu%65"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "an attack value",
                               .highlight = "an attack value"sv,
                               .args = {{.value = "an attack value"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlPath)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_path.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("/path/to/index.php?a=b#frag"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/path/to/index.php",
                               .highlight = "/path/to/index.php"sv,
                               .args = {{.value = "/path/to/index.php"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlPathAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_path.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("/path/to/index.php?a=b#frag"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "/path/to/index.php",
                               .highlight = "/path/to/index.php"sv,
                               .args = {{.value = "/path/to/index.php"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlQuerystring)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_querystring.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value1"), alloc), STRL("/path/to/index.php?a=b#frag"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "a=b",
                               .highlight = "a=b"sv,
                               .args = {{.value = "a=b"sv, .address = "value1"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, UrlQuerystringAlias)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("url_querystring.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&map, STRL("value2"), alloc), STRL("/path/to/index.php?a=b#frag"));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "a=b",
                               .highlight = "a=b"sv,
                               .args = {{.value = "a=b"sv, .address = "value2"}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Mixed)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("mixed.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_set_string_literal(ddwaf_object_insert_key(&map, STRL("value1"), alloc),
        STRL("L3AgIGEgIHRIL3QgIE8vRmlsRS5QSFA/YT1iI2ZyYWc="));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
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

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
