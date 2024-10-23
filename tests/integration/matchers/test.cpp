// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest/utils.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/matchers/";

TEST(TestIntegrationOperation, StringEquals)
{
    auto rule = read_file("equals.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_string(&value, "arachni");
    ddwaf_object_map_add(&map, "input", &value);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1-string-equals",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "equals",
                               .highlight = "",
                               .args = {{
                                   .value = "arachni",
                                   .address = "input",
                               }}}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestIntegrationOperation, BoolEquals)
{
    auto rule = read_file("equals.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_bool(&value, false);
    ddwaf_object_map_add(&map, "input", &value);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2-bool-equals",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{
                               .op = "equals",
                               .highlight = "",
                               .args = {{
                                   .value = "false",
                                   .address = "input",
                               }},
                           }}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestIntegrationOperation, SignedEquals)
{
    auto rule = read_file("equals.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_signed(&value, -42);
    ddwaf_object_map_add(&map, "input", &value);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out, {.id = "3",
                           .name = "rule3-signed-equals",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "equals",
                               .highlight = "",
                               .args = {{
                                   .value = "-42",
                                   .address = "input",
                               }}}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestIntegrationOperation, UnsignedEquals)
{
    auto rule = read_file("equals.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_unsigned(&value, 42);
    ddwaf_object_map_add(&map, "input", &value);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out, {.id = "4",
                           .name = "rule4-unsigned-equals",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{
                               .op = "equals",
                               .highlight = "",
                               .args = {{
                                   .value = "42",
                                   .address = "input",
                               }},
                           }}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestIntegrationOperation, FloatEquals)
{
    auto rule = read_file("equals.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_float(&value, 42.01);
    ddwaf_object_map_add(&map, "input", &value);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out, {.id = "5",
                           .name = "rule5-float-equals",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{
                               .op = "equals",
                               .highlight = "",
                               .args = {{
                                   .value = "42.01",
                                   .address = "input",
                               }},
                           }}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestIntegrationOperation, PhraseMatch)
{
    auto rule = read_file("phrase_match.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_string(&value, "string00");
    ddwaf_object_map_add(&map, "input1", &value);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1-phrase-match",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "phrase_match",
                               .highlight = "string00",
                               .args = {{
                                   .value = "string00",
                                   .address = "input1",
                               }}}}});

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestIntegrationOperation, PhraseMatchWordBound)
{
    auto rule = read_file("phrase_match.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object value;
        ddwaf_object_string(&value, "string01;");
        ddwaf_object_map_add(&map, "input2", &value);

        ddwaf_result out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_FALSE(out.timeout);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2-phrase-match-word-bound",
                               .tags = {{"type", "flow"}, {"category", "category"}},
                               .matches = {{.op = "phrase_match",
                                   .highlight = "string01",
                                   .args = {{
                                       .value = "string01;",
                                       .address = "input2",
                                   }}}}});

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object map = DDWAF_OBJECT_MAP;
        ddwaf_object value;
        ddwaf_object_string(&value, "string010");
        ddwaf_object_map_add(&map, "input2", &value);

        ddwaf_result out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
        EXPECT_FALSE(out.timeout);

        ddwaf_result_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

} // namespace
