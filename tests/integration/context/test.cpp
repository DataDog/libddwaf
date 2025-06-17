// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/context/";

TEST(TestContextIntegration, Basic)
{
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Setup the parameter structure
    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object subMap = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;
    ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule2"));
    ddwaf_object_map_add(&subMap, "key", ddwaf_object_string(&tmp, "rule3"));
    ddwaf_object_map_add(&parameter, "value2", &subMap); // ddwaf_object_string(&,"rule3"));

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);

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

    ddwaf_object_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, KeyPaths)
{
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor5.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;
    ddwaf_object param = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&param, "x", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&root, "param", &param);

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);

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

    ddwaf_object_free(&ret);

    root = DDWAF_OBJECT_MAP;
    param = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&param, "z", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&root, "param", &param);

    EXPECT_EQ(ddwaf_run(context, &root, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);

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
    ddwaf_object_free(&ret);
    ddwaf_context_destroy(context);

    context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Generate a wrapper
    root = DDWAF_OBJECT_MAP;
    param = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&param, "y", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&root, "param", &param);

    EXPECT_EQ(ddwaf_run(context, &root, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);

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

    ddwaf_object_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, MissingParameter)
{
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Generate a wrapper
    ddwaf_object param = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
    ddwaf_object_map_add(&param, "param", ddwaf_object_signed(&tmp, 42));

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_run(context, &param, nullptr, true, &ret, LONG_TIME), DDWAF_OK);

    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *events = ddwaf_object_find(&ret, STRL("events"));
    EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(events), 0);

    ddwaf_object_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, InvalidUTF8Input)
{
    // Initialize a WAF rule
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: values}, {address: keys}], regex: bla}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Generate a wrapper
    std::string ba1 = "keys";
    std::string ba2 = "values";
    ddwaf_object param = DDWAF_OBJECT_MAP;
    ddwaf_object mapItem;
    ddwaf_object tmp;
    ddwaf_object_string(&mapItem, "\xF0\x82\x82\xAC\xC1"
                                  "bla");

    ddwaf_object_map_addl(&param, ba1.c_str(), ba1.length(), &mapItem);
    ddwaf_object_map_addl(&param, ba2.c_str(), ba2.length(), ddwaf_object_map(&tmp));

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_run(context, &param, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);

    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *events = ddwaf_object_find(&ret, STRL("events"));
    auto data = ddwaf::test::object_to_json(*events);

    std::size_t length;
    const char *str = ddwaf_object_get_string(&mapItem, &length);
    auto pos = data.find(std::string_view{str, length});
    EXPECT_TRUE(pos != std::string::npos);

    ddwaf_object_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, SingleCollectionMatch)
{
    // NOTE: this test only works due to the order of the rules in the ruleset
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor3.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param1 = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param1, "param1", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param1, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param, "param2", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, nullptr, true, &ret, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *events = ddwaf_object_find(&ret, STRL("events"));
        EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_size(events), 0);

        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, MultiCollectionMatches)
{
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor4.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param, "param1", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "Pony"));

        EXPECT_EQ(ddwaf_run(context, &param, nullptr, true, &ret, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        const auto *events = ddwaf_object_find(&ret, STRL("events"));
        EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_size(events), 0);

        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param, "param2", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, Timeout)
{
    auto rule = read_file<ddwaf_object>("slow.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;
    ddwaf_object_map_add(&param, "pm_param", ddwaf_object_string(&tmp, "aaaabbbbbaaa"));

    EXPECT_EQ(ddwaf_run(context, &param, nullptr, true, &ret, SHORT_TIME), DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_TRUE(ddwaf_object_get_bool(timeout));

    ddwaf_object_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, ParameterOverride)
{
    auto rule = read_file<ddwaf_object>("processor6.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param1 = DDWAF_OBJECT_MAP;
    ddwaf_object param2 = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;

    ddwaf_object_map_add(&param1, "arg1", ddwaf_object_string(&tmp, "not string 1"));
    ddwaf_object_map_add(&param1, "arg2", ddwaf_object_string(&tmp, "string 2"));
    ddwaf_object_map_add(&param2, "arg1", ddwaf_object_string(&tmp, "string 1"));

    // Run with both arg1 and arg2, but arg1 is wrong
    //	// Run with just arg1
    ddwaf_object ret;
    auto code = ddwaf_run(context, &param1, nullptr, true, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    ddwaf_object_free(&ret);

    // Override `arg1`
    code = ddwaf_run(context, &param2, nullptr, true, &ret, LONG_TIME);
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

    ddwaf_object_free(&ret);

    // Run again without change
    code = ddwaf_run(context, ddwaf_object_map(&tmp), nullptr, true, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_OK);

    timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    ddwaf_object_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, DuplicateEphemeralMatch)
{
    auto rule = read_file<ddwaf_object>("processor3.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object param1 = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&param1, "param1", ddwaf_object_string(&tmp, "Sqreen"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &param1, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object tmp;
        ddwaf_object param1 = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&param1, "param1", ddwaf_object_string(&tmp, "Sqreen"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &param1, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, EphemeralAndPersistentMatches)
{
    auto rule = read_file<ddwaf_object>("processor6.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object persistent = DDWAF_OBJECT_MAP;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&persistent, "arg1", ddwaf_object_string(&tmp, "string 1"));
        ddwaf_object_map_add(&ephemeral, "arg2", ddwaf_object_string(&tmp, "string 2"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, &persistent, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg2", ddwaf_object_string(&tmp, "string 8"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg2", ddwaf_object_string(&tmp, "string 3"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, EphemeralNonPriorityAndEphemeralPriority)
{
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg1", ddwaf_object_string(&tmp, "string 1"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg1", ddwaf_object_string(&tmp, "string 1"));
        ddwaf_object_map_add(&ephemeral, "arg2", ddwaf_object_string(&tmp, "string 8"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, EphemeralPriorityAndEphemeralNonPriority)
{
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg1", ddwaf_object_string(&tmp, "string 1"));
        ddwaf_object_map_add(&ephemeral, "arg2", ddwaf_object_string(&tmp, "string 8"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg1", ddwaf_object_string(&tmp, "string 1"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, EphemeralNonPriorityAndPersistentPriority)
{
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg1", ddwaf_object_string(&tmp, "string 1"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object tmp;
        ddwaf_object persistent = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&persistent, "arg2", ddwaf_object_string(&tmp, "string 8"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, &persistent, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, ReplaceEphemeral)
{
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg1", ddwaf_object_string(&tmp, "string 1"));
        ddwaf_object_map_add(&ephemeral, "arg1", ddwaf_object_string(&tmp, "string 1"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, EphemeralPriorityAndPersistentNonPriority)
{
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg2", ddwaf_object_string(&tmp, "string 8"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object tmp;
        ddwaf_object persistent = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&persistent, "arg1", ddwaf_object_string(&tmp, "string 1"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, &persistent, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);
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

        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, PersistentPriorityAndEphemeralNonPriority)
{
    auto rule = read_file<ddwaf_object>("processor7.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object tmp;
        ddwaf_object persistent = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&persistent, "arg2", ddwaf_object_string(&tmp, "string 8"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, &persistent, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .actions = {"block"},
                               .matches = {{.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 8"sv,
                                   .args = {{
                                       .value = "string 8"sv,
                                       .address = "arg2",
                                   }}}}});
        ddwaf_object_free(&ret);
    }

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&ephemeral, "arg1", ddwaf_object_string(&tmp, "string 1"));

        ddwaf_object ret;
        EXPECT_EQ(ddwaf_run(context, nullptr, &ephemeral, true, &ret, LONG_TIME), DDWAF_OK);
        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, WafContextEventAddress)
{
    auto rule = read_json_file("context_event_address.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object body = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&body, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.body", &body);

        ddwaf_object query = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&query, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.query", &query);

        ddwaf_object_map_add(
            &map, "server.request.uri.raw", ddwaf_object_string(&tmp, "/path/to/resource/?key="));
        ddwaf_object_map_add(&map, "server.request.method", ddwaf_object_string(&tmp, "PuT"));

        ddwaf_object_map_add(&map, "waf.trigger", ddwaf_object_string(&tmp, "irrelevant"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 0);

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object map = DDWAF_OBJECT_MAP;

        ddwaf_object body = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&body, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.body", &body);

        ddwaf_object query = DDWAF_OBJECT_MAP;
        ddwaf_object_map_add(&query, "key", ddwaf_object_invalid(&tmp));
        ddwaf_object_map_add(&map, "server.request.query", &query);

        ddwaf_object_map_add(
            &map, "server.request.uri.raw", ddwaf_object_string(&tmp, "/path/to/resource/?key="));
        ddwaf_object_map_add(&map, "server.request.method", ddwaf_object_string(&tmp, "PuT"));

        ddwaf_object_map_add(&map, "waf.trigger", ddwaf_object_string(&tmp, "rule"));

        ddwaf_object out;
        ASSERT_EQ(ddwaf_run(context, &map, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *attributes = ddwaf_object_find(&out, STRL("attributes"));
        EXPECT_EQ(ddwaf_object_size(attributes), 1);

        auto json = test::object_to_json(*attributes);
        EXPECT_STR(
            json, R"({"_dd.appsec.fp.http.endpoint":"http-put-729d56c3-2c70e12b-2c70e12b"})");

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, MultipleModuleSingleCollectionMatch)
{
    // NOTE: this test only works due to the order of the rules in the ruleset
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("same-type-different-module.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param1 = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;
    ddwaf_object_map_add(&param1, "param1", ddwaf_object_string(&tmp, "Sqreen"));

    EXPECT_EQ(ddwaf_run(context, &param1, nullptr, true, &ret, LONG_TIME), DDWAF_MATCH);
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
    ddwaf_object_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, TimeoutBeyondLimit)
{
    // Initialize a WAF rule
    auto rule = read_file<ddwaf_object>("processor.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Setup the parameter structure
    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object subMap = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;
    ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule2"));
    ddwaf_object_map_add(&subMap, "key", ddwaf_object_string(&tmp, "rule3"));
    ddwaf_object_map_add(&parameter, "value2", &subMap); // ddwaf_object_string(&,"rule3"));

    ddwaf_object ret;
    EXPECT_EQ(
        ddwaf_run(context, &parameter, nullptr, true, &ret, std::numeric_limits<uint64_t>::max()),
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

    ddwaf_object_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
