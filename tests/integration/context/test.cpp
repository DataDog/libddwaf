// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../test_utils.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/context/";

TEST(TestContextIntegration, Basic)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("processor.yaml", base_dir);
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

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &parameter, &ret, LONG_TIME), DDWAF_MATCH);

    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                                           .op_value = "rule2",
                                           .address = "value",
                                           .value = "rule2",
                                           .highlight = "rule2"},
                               {.op = "match_regex",
                                   .op_value = "rule3",
                                   .address = "value2",
                                   .path = {"key"},
                                   .value = "rule3",
                                   .highlight = "rule3"}}});

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, KeyPaths)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("processor5.yaml", base_dir);
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

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &root, &ret, LONG_TIME), DDWAF_MATCH);

    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "Sqreen",
                               .address = "param",
                               .path = {"x"},
                               .value = "Sqreen",
                               .highlight = "Sqreen"}}});

    ddwaf_result_free(&ret);

    root = DDWAF_OBJECT_MAP;
    param = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&param, "z", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&root, "param", &param);

    EXPECT_EQ(ddwaf_run(context, &root, &ret, LONG_TIME), DDWAF_MATCH);

    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow2"}, {"category", "category2"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "Sqreen",
                               .address = "param",
                               .path = {"z"},
                               .value = "Sqreen",
                               .highlight = "Sqreen"}}});
    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);

    context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Generate a wrapper
    root = DDWAF_OBJECT_MAP;
    param = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&param, "y", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&root, "param", &param);

    EXPECT_EQ(ddwaf_run(context, &root, &ret, LONG_TIME), DDWAF_MATCH);

    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                               .op_value = "Sqreen",
                               .address = "param",
                               .path = {"y"},
                               .value = "Sqreen",
                               .highlight = "Sqreen"}}});

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, MissingParameter)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("processor.yaml", base_dir);
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

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_OK);

    EXPECT_FALSE(ret.timeout);
    EXPECT_EQ(ddwaf_object_type(&ret.events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(&ret.events), 0);

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, InvalidUTF8Input)
{
    // Initialize a PowerWAF rule
    auto rule = readRule(
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

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MATCH);

    EXPECT_FALSE(ret.timeout);

    auto data = ddwaf::test::object_to_json(ret.events);
    auto pos = data.find(mapItem.stringValue);
    EXPECT_TRUE(pos != std::string::npos);

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, SingleCollectionMatch)
{
    // NOTE: this test only works due to the order of the rules in the ruleset
    // Initialize a PowerWAF rule
    auto rule = readFile("processor3.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param1 = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param1, "param1", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param1, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_FALSE(ret.timeout);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "Sqreen",
                                   .address = "param1",
                                   .value = "Sqreen",
                                   .highlight = "Sqreen"}}});
        ddwaf_result_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param, "param2", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_OK);
        EXPECT_FALSE(ret.timeout);
        EXPECT_EQ(ddwaf_object_type(&ret.events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_size(&ret.events), 0);

        ddwaf_result_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, MultiCollectionMatches)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("processor4.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param, "param1", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_FALSE(ret.timeout);
        EXPECT_EVENTS(ret, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "flow1"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "Sqreen",
                                   .address = "param1",
                                   .value = "Sqreen",
                                   .highlight = "Sqreen"}}});
        ddwaf_result_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "Pony"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_OK);
        EXPECT_FALSE(ret.timeout);
        EXPECT_EQ(ddwaf_object_type(&ret.events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_size(&ret.events), 0);

        ddwaf_result_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP;
        ddwaf_object tmp;
        ddwaf_object_map_add(&param, "param2", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MATCH);
        EXPECT_FALSE(ret.timeout);
        EXPECT_EVENTS(ret, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "flow2"}, {"category", "category2"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "Sqreen",
                                   .address = "param2",
                                   .value = "Sqreen",
                                   .highlight = "Sqreen"}}});
        ddwaf_result_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextIntegration, Timeout)
{
    auto rule = readFile("slow.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param = DDWAF_OBJECT_MAP;
    ddwaf_object tmp;
    ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "aaaabbbbbaaa"));

    EXPECT_EQ(ddwaf_run(context, &param, &ret, SHORT_TIME), DDWAF_OK);
    EXPECT_TRUE(ret.timeout);

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
