// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../test.h"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/transformers/";
} // namespace

TEST(TestTransformers, Base64Decode)
{
    auto rule = readFile("base64_decode.yaml", base_dir);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out,{
        .id = "1",
        .name = "rule1",
        .tags = {{"type", "flow1"}, {"category", "category1"}},
        .matches = {{
            .op = "is_sqli",
            .address = "value1",
            .value = "'OR 1=1/*",
            .highlight = "s&1c"}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}


TEST(TestTransformers, Base64DecodeAlias)
{
    auto rule = readFile("base64_decode.yaml", base_dir);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out,{
        .id = "2",
        .name = "rule2",
        .tags = {{"type", "flow1"}, {"category", "category1"}},
        .matches = {{
            .op = "is_sqli",
            .address = "value2",
            .value = "'OR 1=1/*",
            .highlight = "s&1c"}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64Encode)
{
    auto rule = readFile("base64_encode.yaml", base_dir);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out,{
        .id = "1",
        .name = "rule1",
        .tags = {{"type", "flow1"}, {"category", "category1"}},
        .matches = {{
            .op = "match_regex",
            .op_value = "J09SIDE9MS8q",
            .address = "value1",
            .value = "J09SIDE9MS8q",
            .highlight = "J09SIDE9MS8q"}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, Base64EncodeAlias)
{
    auto rule = readFile("base64_encode.yaml", base_dir);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out,{
        .id = "2",
        .name = "rule2",
        .tags = {{"type", "flow1"}, {"category", "category1"}},
        .matches = {{
            .op = "match_regex",
            .op_value = "J09SIDE9MS8q",
            .address = "value2",
            .value = "J09SIDE9MS8q",
            .highlight = "J09SIDE9MS8q"}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CompressWhitespace)
{
    auto rule = readFile("compress_whitespace.yaml", base_dir);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out,{
        .id = "1",
        .name = "rule1",
        .tags = {{"type", "flow1"}, {"category", "category1"}},
        .matches = {{
            .op = "match_regex",
            .op_value = "attack value",
            .address = "value1",
            .value = "attack value",
            .highlight = "attack value"}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CompressWhitespaceAlias)
{
    auto rule = readFile("compress_whitespace.yaml", base_dir);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out,{
        .id = "2",
        .name = "rule2",
        .tags = {{"type", "flow1"}, {"category", "category1"}},
        .matches = {{
            .op = "match_regex",
            .op_value = "attack value",
            .address = "value2",
            .value = "attack value",
            .highlight = "attack value"}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestTransformers, CssDecode)
{
    auto rule = readFile("css_decode.yaml", base_dir);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out,{
        .id = "1",
        .name = "rule1",
        .tags = {{"type", "flow1"}, {"category", "category1"}},
        .matches = {{
            .op = "match_regex",
            .op_value = "CSS transformations",
            .address = "value1",
            .value = "CSS transformations",
            .highlight = "CSS transformations"}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}


TEST(TestTransformers, CssDecodeAlias)
{
    auto rule = readFile("css_decode.yaml", base_dir);
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

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out,{
        .id = "2",
        .name = "rule2",
        .tags = {{"type", "flow1"}, {"category", "category1"}},
        .matches = {{
            .op = "match_regex",
            .op_value = "CSS transformations",
            .address = "value2",
            .value = "CSS transformations",
            .highlight = "CSS transformations"}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
