// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/context/";

TEST(TestContextIntegration, Basic)
{
    auto *alloc = ddwaf_get_default_allocator();
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Setup the parameter structure

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule2"), alloc);

    auto *subMap = ddwaf_object_insert_key(&parameter, STRL("value2"), alloc);
    ddwaf_object_set_map(subMap, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(subMap, STRL("key"), alloc), STRL("rule3"), alloc);

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &ret, LONG_TIME), DDWAF_MATCH);

    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                                           .op_value = "rule2",
                                           .highlight = "rule2"sv,
                                           .args = {{
                                               .value = "rule2"sv,
                                               .address = "value",
                                           }}},
                               {.op = "match_regex",
                                   .op_value = "rule3",
                                   .highlight = "rule3"sv,
                                   .args = {{
                                       .value = "rule3"sv,
                                       .address = "value2",
                                       .path = {"key"},
                                   }}}}});

    ddwaf_object_destroy(&ret, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, KeyPaths)
{
    auto *alloc = ddwaf_get_default_allocator();
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor5.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    auto *param = ddwaf_object_insert_key(&root, STRL("param"), alloc);
    ddwaf_object_set_map(param, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(param, STRL("x"), alloc), STRL("Sqreen"), alloc);

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &ret, LONG_TIME), DDWAF_MATCH);

    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "Sqreen",
                               .highlight = "Sqreen"sv,
                               .args = {{
                                   .value = "Sqreen"sv,
                                   .address = "param",
                                   .path = {"x"},
                               }}}}});

    ddwaf_object_destroy(&ret, alloc);

    ddwaf_object_set_map(&root, 1, alloc);
    param = ddwaf_object_insert_key(&root, STRL("param"), alloc);
    ddwaf_object_set_map(param, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(param, STRL("z"), alloc), STRL("Sqreen"), alloc);

    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &ret, LONG_TIME), DDWAF_MATCH);

    timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(ret, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow2"}, {"category", "category2"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "Sqreen",
                               .highlight = "Sqreen"sv,
                               .args = {{
                                   .value = "Sqreen"sv,
                                   .address = "param",
                                   .path = {"z"},
                               }}}}});
    ddwaf_object_destroy(&ret, alloc);
    ddwaf_context_destroy(context);

    context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Generate a wrapper
    ddwaf_object_set_map(&root, 1, alloc);
    param = ddwaf_object_insert_key(&root, STRL("param"), alloc);
    ddwaf_object_set_map(param, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(param, STRL("y"), alloc), STRL("Sqreen"), alloc);

    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &ret, LONG_TIME), DDWAF_MATCH);

    timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "Sqreen",
                               .highlight = "Sqreen"sv,
                               .args = {{
                                   .value = "Sqreen"sv,
                                   .address = "param",
                                   .path = {"y"},
                               }}}}});

    ddwaf_object_destroy(&ret, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, MissingParameter)
{
    auto *alloc = ddwaf_get_default_allocator();
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Generate a wrapper

    ddwaf_object param;
    ddwaf_object_set_map(&param, 1, alloc);
    ddwaf_object_set_signed(ddwaf_object_insert_key(&param, STRL("param"), alloc), 42);

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME), DDWAF_OK);

    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *events = ddwaf_object_find(&ret, STRL("events"));
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 0);

    ddwaf_object_destroy(&ret, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, InvalidUTF8Input)
{
    auto *alloc = ddwaf_get_default_allocator();
    // Initialize a WAF rule
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: values}, {address: keys}], regex: bla}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    std::string ba2 = "values";
    ddwaf_object param;
    ddwaf_object_set_map(&param, 1, alloc);

    auto *item = ddwaf_object_insert_key(&param, STRL("values"), alloc);
    ddwaf_object_set_map(item, 0, alloc);

    item = ddwaf_object_insert_key(&param, STRL("keys"), alloc);
    ddwaf_object_set_string(item,
        STRL("\xF0\x82\x82\xAC\xC1"
             "bla"),
        alloc);

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME), DDWAF_MATCH);

    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *events = ddwaf_object_find(&ret, STRL("events"));
    auto data = ddwaf::test::object_to_json(*events);

    std::size_t length;
    const char *str = ddwaf_object_get_string(item, &length);
    auto pos = data.find(std::string_view{str, length});
    EXPECT_TRUE(pos != std::string::npos);

    ddwaf_object_destroy(&ret, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, SingleCollectionMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    // NOTE: this test only works due to the order of the rules in the ruleset
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor3.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_object ret;
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param1;
        ddwaf_object_set_map(&param1, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&param1, STRL("param1"), alloc), STRL("Sqreen"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &param1, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "Sqreen",
                                   .highlight = "Sqreen"sv,
                                   .args = {{
                                       .value = "Sqreen"sv,
                                       .address = "param1",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
    }

    {
        ddwaf_object param;
        ddwaf_object_set_map(&param, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&param, STRL("param2"), alloc), STRL("Sqreen"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *events = ddwaf_object_find(&ret, STRL("events"));
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        ddwaf_object_destroy(&ret, alloc);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, MultiCollectionMatches)
{
    auto *alloc = ddwaf_get_default_allocator();
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor4.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_object ret;
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param;
        ddwaf_object_set_map(&param, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&param, STRL("param1"), alloc), STRL("Sqreen"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "Sqreen",
                                   .highlight = "Sqreen"sv,
                                   .args = {{
                                       .value = "Sqreen"sv,
                                       .address = "param1",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
    }

    {
        ddwaf_object param;
        ddwaf_object_set_map(&param, 1, alloc);
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&param, STRL("param"), alloc), STRL("Pony"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        const auto *events = ddwaf_object_find(&ret, STRL("events"));
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        ddwaf_object_destroy(&ret, alloc);
    }

    {
        ddwaf_object param;
        ddwaf_object_set_map(&param, 1, alloc);
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&param, STRL("param2"), alloc), STRL("Sqreen"), alloc);

        EXPECT_EQ(ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "flow2"}, {"category", "category2"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "Sqreen",
                                   .highlight = "Sqreen"sv,
                                   .args = {{
                                       .value = "Sqreen"sv,
                                       .address = "param2",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, Timeout)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("slow.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_object ret;
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object param;
    ddwaf_object_set_map(&param, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param, STRL("pm_param"), alloc), STRL("aaaabbbbbaaa"), alloc);

    EXPECT_EQ(ddwaf_context_eval(context, &param, alloc, &ret, SHORT_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_TRUE(ddwaf_object_get_bool(timeout));

    ddwaf_object_destroy(&ret, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, ParameterOverride)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("processor6.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object param1;
    ddwaf_object_set_map(&param1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param1, STRL("arg1"), alloc), STRL("not string 1"), alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param1, STRL("arg2"), alloc), STRL("string 2"), alloc);

    ddwaf_object param2;
    ddwaf_object_set_map(&param2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param2, STRL("arg1"), alloc), STRL("string 1"), alloc);

    // Run with both arg1 and arg2, but arg1 is wrong
    //	// Run with just arg1
    ddwaf_object ret;
    auto code = ddwaf_context_eval(context, &param1, alloc, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    ddwaf_object_destroy(&ret, alloc);

    // Override `arg1`
    code = ddwaf_context_eval(context, &param2, alloc, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MATCH);
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                                           .op_value = "^string.*",
                                           .highlight = "string 1"sv,
                                           .args = {{
                                               .value = "string 1"sv,
                                               .address = "arg1",
                                           }}},
                               {.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 2"sv,
                                   .args = {{
                                       .value = "string 2"sv,
                                       .address = "arg2",
                                   }}}}});

    ddwaf_object_destroy(&ret, alloc);

    // Run again without change
    ddwaf_object empty;
    ddwaf_object_set_map(&empty, 0, alloc);
    code = ddwaf_context_eval(context, &empty, alloc, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_OK);

    timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    ddwaf_object_destroy(&ret, alloc);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, DuplicateSubcontextMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("processor3.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param1;
        ddwaf_object_set_map(&param1, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&param1, STRL("param1"), alloc), STRL("Sqreen"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &param1, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "Sqreen",
                                   .highlight = "Sqreen"sv,
                                   .args = {{
                                       .value = "Sqreen"sv,
                                       .address = "param1",
                                   }}}}});
        ddwaf_subcontext_destroy(subctx);
        ddwaf_object_destroy(&ret, alloc);
    }

    {
        ddwaf_object param1;
        ddwaf_object_set_map(&param1, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&param1, STRL("param1"), alloc), STRL("Sqreen"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &param1, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "Sqreen",
                                   .highlight = "Sqreen"sv,
                                   .args = {{
                                       .value = "Sqreen"sv,
                                       .address = "param1",
                                   }}}}});
        ddwaf_subcontext_destroy(subctx);
        ddwaf_object_destroy(&ret, alloc);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, SubcontextAndContextMatches)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("processor6.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object persistent;
    ddwaf_object_set_map(&persistent, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&persistent, STRL("arg1"), alloc), STRL("string 1"), alloc);

    EXPECT_EQ(ddwaf_context_eval(context, &persistent, alloc, nullptr, LONG_TIME), DDWAF_OK);

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg2"), alloc), STRL("string 2"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                               .op_value = "^string.*",
                                               .highlight = "string 1"sv,
                                               .args = {{
                                                   .value = "string 1"sv,
                                                   .address = "arg1",
                                               }}},
                                   {.op = "match_regex",
                                       .op_value = ".*",
                                       .highlight = "string 2"sv,
                                       .args = {{
                                           .value = "string 2"sv,
                                           .address = "arg2",
                                       }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg2"), alloc), STRL("string 8"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                               .op_value = "^string.*",
                                               .highlight = "string 1"sv,
                                               .args = {{
                                                   .value = "string 1"sv,
                                                   .address = "arg1",
                                               }}},
                                   {.op = "match_regex",
                                       .op_value = ".*",
                                       .highlight = "string 8"sv,
                                       .args = {{
                                           .value = "string 8"sv,
                                           .address = "arg2",
                                       }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg2"), alloc), STRL("string 3"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
        ddwaf_object ret;

        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                               .op_value = "^string.*",
                                               .highlight = "string 1"sv,
                                               .args = {{
                                                   .value = "string 1"sv,
                                                   .address = "arg1",
                                               }}},
                                   {.op = "match_regex",
                                       .op_value = ".*",
                                       .highlight = "string 3"sv,
                                       .args = {{
                                           .value = "string 3"sv,
                                           .address = "arg2",
                                       }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, SubcontextNonPriorityAndSubcontextPriority)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg1"), alloc), STRL("string 1"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^string.*",
                                   .highlight = "string 1"sv,
                                   .args = {{
                                       .value = "string 1"sv,
                                       .address = "arg1",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg1"), alloc), STRL("string 1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg2"), alloc), STRL("string 8"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, EphemeralPriorityAndEphemeralNonPriority)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg1"), alloc), STRL("string 1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg2"), alloc), STRL("string 8"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg1"), alloc), STRL("string 1"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^string.*",
                                   .highlight = "string 1"sv,
                                   .args = {{
                                       .value = "string 1"sv,
                                       .address = "arg1",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, EphemeralNonPriorityAndPersistentPriority)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg1"), alloc), STRL("string 1"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^string.*",
                                   .highlight = "string 1"sv,
                                   .args = {{
                                       .value = "string 1"sv,
                                       .address = "arg1",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        ddwaf_object persistent;
        ddwaf_object_set_map(&persistent, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&persistent, STRL("arg2"), alloc), STRL("string 8"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_context_eval(context, &persistent, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, ReplaceEphemeral)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg1"), alloc), STRL("string 1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg1"), alloc), STRL("string 1"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^string.*",
                                   .highlight = "string 1"sv,
                                   .args = {{
                                       .value = "string 1"sv,
                                       .address = "arg1",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, EphemeralPriorityAndPersistentNonPriority)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg2"), alloc), STRL("string 8"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    {
        ddwaf_object persistent;
        ddwaf_object_set_map(&persistent, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&persistent, STRL("arg1"), alloc), STRL("string 1"), alloc);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_context_eval(context, &persistent, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "^string.*",
                                   .highlight = "string 1"sv,
                                   .args = {{
                                       .value = "string 1"sv,
                                       .address = "arg1",
                                   }}}}});

        ddwaf_object_destroy(&ret, alloc);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, PersistentPriorityAndEphemeralNonPriority)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object persistent;
        ddwaf_object_set_map(&persistent, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&persistent, STRL("arg2"), alloc), STRL("string 8"), alloc);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_context_eval(context, &persistent, alloc, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .block_id = "*",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_destroy(&ret, alloc);
    }

    {
        ddwaf_object ephemeral;
        ddwaf_object_set_map(&ephemeral, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&ephemeral, STRL("arg1"), alloc), STRL("string 1"), alloc);

        ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &ret, LONG_TIME), DDWAF_OK);
        ddwaf_object_destroy(&ret, alloc);
        ddwaf_subcontext_destroy(subctx);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, WafContextEventAddress)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_json_file("context_event_address.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 5, alloc);

        auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(body, 1, alloc);
        ddwaf_object_insert_key(body, STRL("key"), alloc);

        auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
        ddwaf_object_set_map(query, 1, alloc);
        ddwaf_object_insert_key(query, STRL("key"), alloc);

        ddwaf_object_set_string(
            ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
            STRL("/path/to/resource/?key="), alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc),
            STRL("PuT"), alloc);

        ddwaf_object_set_string(
            ddwaf_object_insert_key(&map, STRL("waf.trigger"), alloc), STRL("irrelevant"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object map;
        ddwaf_object_set_map(&map, 5, alloc);

        auto *body = ddwaf_object_insert_key(&map, STRL("server.request.body"), alloc);
        ddwaf_object_set_map(body, 1, alloc);
        ddwaf_object_insert_key(body, STRL("key"), alloc);

        auto *query = ddwaf_object_insert_key(&map, STRL("server.request.query"), alloc);
        ddwaf_object_set_map(query, 1, alloc);
        ddwaf_object_insert_key(query, STRL("key"), alloc);

        ddwaf_object_set_string(
            ddwaf_object_insert_key(&map, STRL("server.request.uri.raw"), alloc),
            STRL("/path/to/resource/?key="), alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&map, STRL("server.request.method"), alloc),
            STRL("PuT"), alloc);

        ddwaf_object_set_string(
            ddwaf_object_insert_key(&map, STRL("waf.trigger"), alloc), STRL("rule"), alloc);

        ddwaf_object out;
        ASSERT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        auto json = test::object_to_json(*attributes);
        EXPECT_STR(
            json, R"({"_dd.appsec.fp.http.endpoint":"http-put-729d56c3-2c70e12b-2c70e12b"})");

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, MultipleModuleSingleCollectionMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    // NOTE: this test only works due to the order of the rules in the ruleset
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("same-type-different-module.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_object ret;
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object param1;
    ddwaf_object_set_map(&param1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param1, STRL("param1"), alloc), STRL("Sqreen"), alloc);

    EXPECT_EQ(ddwaf_context_eval(context, &param1, alloc, &ret, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(ret,
        {.id = "1",
            .name = "rule1",
            .tags = {{"type", "flow1"}, {"category", "category1"}, {"module", "rasp"}},
            .matches = {{.op = "match_regex",
                .op_value = "Sqreen",
                .highlight = "Sqreen"sv,
                .args = {{
                    .value = "Sqreen"sv,
                    .address = "param1",
                }}}}},
        {.id = "2",
            .name = "rule2",
            .tags = {{"type", "flow1"}, {"category", "category1"}},
            .matches = {{.op = "match_regex",
                .op_value = "Sqreen",
                .highlight = "Sqreen"sv,
                .args = {{
                    .value = "Sqreen"sv,
                    .address = "param1",
                }}}}});
    ddwaf_object_destroy(&ret, alloc);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, TimeoutBeyondLimit)
{
    auto *alloc = ddwaf_get_default_allocator();
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Setup the parameter structure

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule2"), alloc);

    auto *subMap = ddwaf_object_insert_key(&parameter, STRL("value2"), alloc);
    ddwaf_object_set_map(subMap, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(subMap, STRL("key"), alloc), STRL("rule3"), alloc);

    ddwaf_object ret;
    EXPECT_EQ(
        ddwaf_context_eval(context, &parameter, alloc, &ret, std::numeric_limits<uint64_t>::max()),
        DDWAF_MATCH);

    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                                           .op_value = "rule2",
                                           .highlight = "rule2"sv,
                                           .args = {{
                                               .value = "rule2"sv,
                                               .address = "value",
                                           }}},
                               {.op = "match_regex",
                                   .op_value = "rule3",
                                   .highlight = "rule3"sv,
                                   .args = {{
                                       .value = "rule3"sv,
                                       .address = "value2",
                                       .path = {"key"},
                                   }}}}});

    ddwaf_object_destroy(&ret, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
