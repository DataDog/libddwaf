// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestPWProcessor, TestOutput)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("processor.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Setup the parameter structure
    ddwaf_object parameter = DDWAF_OBJECT_MAP, subMap = DDWAF_OBJECT_MAP, tmp;
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

TEST(TestPWProcessor, TestKeyPaths)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("processor5.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root = DDWAF_OBJECT_MAP, tmp, param = DDWAF_OBJECT_MAP;
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

TEST(TestPWProcessor, TestMissingParameter)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("processor.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Generate a wrapper
    ddwaf_object param = DDWAF_OBJECT_MAP, tmp;

    ddwaf_object_map_add(&param, "param", ddwaf_object_signed(&tmp, 42));

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_OK);

    EXPECT_FALSE(ret.timeout);
    EXPECT_EQ(ret.data, nullptr);

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestInvalidUTF8Input)
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
    std::string ba1 = "keys", ba2 = "values";
    ddwaf_object param = DDWAF_OBJECT_MAP, mapItem, tmp;
    ddwaf_object_string(&mapItem, "\xF0\x82\x82\xAC\xC1"
                                  "bla");

    ddwaf_object_map_addl(&param, ba1.c_str(), ba1.length(), &mapItem);
    ddwaf_object_map_addl(&param, ba2.c_str(), ba2.length(), ddwaf_object_map(&tmp));

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MATCH);

    EXPECT_FALSE(ret.timeout);
    auto pos = std::string{ret.data}.find(mapItem.stringValue);
    EXPECT_TRUE(pos != string::npos);

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

// TEST(TestPWProcessor, TestCache)
//{
////Initialize a PowerWAF rule
// auto rule = readFile("processor2.yaml");
// ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

// ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
// ASSERT_NE(handle, nullptr);
// ddwaf_object_free(&rule);

// ddwaf_result ret;
// ddwaf_context context = ddwaf_context_init(handle);
// ASSERT_NE(context, nullptr);

// ddwaf::context* add = reinterpret_cast<ddwaf::context*>(context);

//{
// ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
// ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "not valid"));

// EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_OK);
// EXPECT_FALSE(ret.timeout);
// ddwaf_result_free(&ret);

// EXPECT_GE(add->processor_.ranCache.size(), 1);
// EXPECT_EQ(add->processor_.ranCache.at(0), match_status::no_match);
//}

//{
// ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
// ddwaf_object_map_add(&param, "param2", ddwaf_object_string(&tmp, "Sqreen"));

// EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_OK);
// EXPECT_FALSE(ret.timeout);
// ddwaf_result_free(&ret);

// EXPECT_EQ(add->processor_.ranCache.at(0), match_status::no_match);
//}

//{
// ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
// ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "Sqreen"));

// EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MATCH);
// EXPECT_FALSE(ret.timeout);
// EXPECT_STREQ(ret.data,
// R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"flow1","category":"category1"}},"rule_matches":[{"operator":"match_regex","operator_value":"Sqreen","parameters":[{"address":"param","key_path":[],"value":"Sqreen","highlight":["Sqreen"]}]},{"operator":"match_regex","operator_value":"Sqreen","parameters":[{"address":"param2","key_path":[],"value":"Sqreen","highlight":["Sqreen"]}]}]}])");

// EXPECT_EQ(add->processor_.ranCache.at(0), match_status::matched);

// ddwaf_result_free(&ret);
//}

// ddwaf_context_destroy(context);
// ddwaf_destroy(handle);
//}

TEST(TestPWProcessor, TestCacheReport)
{
    // NOTE: this test only works due to the order of the rules in the ruleset
    // Initialize a PowerWAF rule
    auto rule = readFile("processor3.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param1 = DDWAF_OBJECT_MAP, tmp;
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
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param2", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_OK);
        EXPECT_FALSE(ret.timeout);
        EXPECT_EQ(ret.data, nullptr);

        ddwaf_result_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestMultiFlowCacheReport)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("processor4.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
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
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "Pony"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_OK);
        EXPECT_FALSE(ret.timeout);
        EXPECT_EQ(ret.data, nullptr);

        ddwaf_result_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
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

// TEST(TestPWProcessor, TestBudget)
//{
////Initialize a PowerWAF rule
// auto rule = readFile("slow.yaml");
// ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

// ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
// ASSERT_NE(handle, nullptr);
// ddwaf_object_free(&rule);

////Generate a wrapper
// ddwaf_object param = DDWAF_OBJECT_MAP, mapItem = DDWAF_OBJECT_ARRAY, array = DDWAF_OBJECT_ARRAY,
// tmp;

// for (int i = 0; i < 500; ++i)
//{
// ddwaf_object_array_add(&array, ddwaf_object_string(&tmp,
// "abbbbbbbbbabababababababaaaaaaaaaaaaaad"));
//}

// ddwaf_object_array_add(&mapItem, &array);
// ddwaf_object_map_add(&param, "rx_param", &mapItem);

// ddwaf::waf* waf = reinterpret_cast<ddwaf::waf*>(handle);
// ddwaf::object_store store(waf->manifest);
// store.insert(param);
// ASSERT_TRUE((bool)store);

////Fetch the rule and flow managers
// auto& flows = waf->flows;

// rapidjson::Document document;
// ddwaf::obfuscator eo;
// PWRetManager rManager(eo);
// ddwaf::processor processor(store, waf->manifest);

// auto deadline = ddwaf::monotonic_clock::now() + chrono::microseconds(50);
// processor.runFlow("flow1", flows["flow1"], rManager, deadline);
// ddwaf_result ret;
// rManager.synthetize(ret);
// EXPECT_EQ(ret.data, nullptr);

// mapItem.parameterName = NULL;

// ddwaf_result_free(&ret);
// ddwaf_destroy(handle);
/*}*/

TEST(TestPWProcessor, TestBudgetRules)
{
    // Initialize a PowerWAF rule
    auto rule = readFile("slow.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "aaaabbbbbaaa"));

    EXPECT_EQ(ddwaf_run(context, &param, &ret, SHORT_TIME), DDWAF_OK);
    EXPECT_TRUE(ret.timeout);

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
