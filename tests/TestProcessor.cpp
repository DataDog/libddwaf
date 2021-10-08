// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestPWProcessor, TestOutput)
{
    //Initialize a PowerWAF rule
    auto rule = readFile("processor.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    //Setup the parameter structure
    ddwaf_object parameter = DDWAF_OBJECT_MAP, subMap = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&parameter, "value", ddwaf_object_string(&tmp, "rule2"));
    ddwaf_object_map_add(&subMap, "key", ddwaf_object_string(&tmp, "rule3"));
    ddwaf_object_map_add(&parameter, "value2", &subMap); //ddwaf_object_string(&,"rule3"));

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &parameter, &ret, LONG_TIME), DDWAF_MONITOR);

    EXPECT_EQ(ret.action, DDWAF_MONITOR);
    EXPECT_STREQ(ret.data, "[{\"ret_code\":1,\"flow\":\"flow1\",\"rule\":\"1\",\"filter\":[{\"operator\":\"match_regex\",\"operator_value\":\"rule2\",\"binding_accessor\":\"value\",\"manifest_key\":\"value\",\"resolved_value\":\"rule2\",\"match_status\":\"rule2\"},{\"operator\":\"match_regex\",\"operator_value\":\"rule3\",\"binding_accessor\":\"value2\",\"manifest_key\":\"value2\",\"key_path\":[\"key\"],\"resolved_value\":\"rule3\",\"match_status\":\"rule3\"}]}]");

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestKeyPaths)
{
    //Initialize a PowerWAF rule
    auto rule = readFile("processor5.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    ddwaf_object root = DDWAF_OBJECT_MAP, tmp, param = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&param, "x", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&root, "param", &param);

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &root, &ret, LONG_TIME), DDWAF_MONITOR);

    EXPECT_EQ(ret.action, DDWAF_MONITOR);
    EXPECT_STREQ(ret.data, R"([{"ret_code":1,"flow":"flow1","rule":"1","filter":[{"operator":"match_regex","operator_value":"Sqreen","binding_accessor":"param","manifest_key":"param:x","key_path":["x"],"resolved_value":"Sqreen","match_status":"Sqreen"}]}])");

    ddwaf_result_free(&ret);

    root  = DDWAF_OBJECT_MAP;
    param = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&param, "z", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&root, "param", &param);

    EXPECT_EQ(ddwaf_run(context, &root, &ret, LONG_TIME), DDWAF_MONITOR);

    EXPECT_EQ(ret.action, DDWAF_MONITOR);
    EXPECT_STREQ(ret.data, R"([{"ret_code":1,"flow":"flow2","rule":"2","filter":[{"operator":"match_regex","operator_value":"Sqreen","binding_accessor":"param","manifest_key":"param:z","key_path":["z"],"resolved_value":"Sqreen","match_status":"Sqreen"}]}])");

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);

    context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    //Generate a wrapper
    root  = DDWAF_OBJECT_MAP;
    param = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&param, "y", ddwaf_object_string(&tmp, "Sqreen"));
    ddwaf_object_map_add(&root, "param", &param);

    EXPECT_EQ(ddwaf_run(context, &root, &ret, LONG_TIME), DDWAF_MONITOR);

    EXPECT_EQ(ret.action, DDWAF_MONITOR);
    EXPECT_STREQ(ret.data, R"([{"ret_code":1,"flow":"flow1","rule":"1","filter":[{"operator":"match_regex","operator_value":"Sqreen","binding_accessor":"param","manifest_key":"param:y","key_path":["y"],"resolved_value":"Sqreen","match_status":"Sqreen"}]}])");

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestMissingParameter)
{
    //Initialize a PowerWAF rule
    auto rule = readFile("processor.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    //Generate a wrapper
    ddwaf_object param = DDWAF_OBJECT_MAP, tmp;

    ddwaf_object_map_add(&param, "param", ddwaf_object_signed(&tmp, 42));

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_GOOD);

    EXPECT_EQ(ret.action, DDWAF_GOOD);
    EXPECT_EQ(ret.data, nullptr);

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestInvalidUTF8Input)
{
    //Initialize a PowerWAF rule
    auto rule = readRule(R"({version: '2.1', rules: [{id: 1, tags: {type: flow1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: values}, {address: keys}], regex: bla}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    //Generate a wrapper
    std::string ba1    = "keys",
                ba2    = "values";
    ddwaf_object param = DDWAF_OBJECT_MAP, mapItem, tmp;
    ddwaf_object_string(&mapItem, "\xF0\x82\x82\xAC\xC1"
                                  "bla");

    ddwaf_object_map_addl(&param, ba1.c_str(), ba1.length(), &mapItem);
    ddwaf_object_map_addl(&param, ba2.c_str(), ba2.length(), ddwaf_object_map(&tmp));

    ddwaf_result ret;
    EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MONITOR);

    EXPECT_EQ(ret.action, DDWAF_MONITOR);
    auto pos = std::string { ret.data }.find(mapItem.stringValue);
    EXPECT_TRUE(pos != string::npos);

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestCache)
{
    //Initialize a PowerWAF rule
    auto rule = readFile("processor2.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    PWAdditive* add = reinterpret_cast<PWAdditive*>(context);

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "not valid"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_GOOD);
        EXPECT_EQ(ret.action, DDWAF_GOOD);
        ddwaf_result_free(&ret);

        EXPECT_GE(add->processor.ranCache.size(), 1);
        EXPECT_FALSE(add->processor.ranCache.at("1").first);
        EXPECT_EQ(add->processor.ranCache.at("1").second, add->processor.runCount);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param2", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_GOOD);
        EXPECT_EQ(ret.action, DDWAF_GOOD);
        ddwaf_result_free(&ret);

        EXPECT_FALSE(add->processor.ranCache.at("1").first);
        EXPECT_EQ(add->processor.ranCache.at("1").second, add->processor.runCount);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MONITOR);
        EXPECT_EQ(ret.action, DDWAF_MONITOR);
        EXPECT_STREQ(ret.data, R"([{"ret_code":1,"flow":"flow1","rule":"1","filter":[{"operator":"match_regex","operator_value":"Sqreen","binding_accessor":"param","manifest_key":"param","resolved_value":"Sqreen","match_status":"Sqreen"},{"operator":"match_regex","operator_value":"Sqreen","binding_accessor":"param2","manifest_key":"param2","resolved_value":"Sqreen","match_status":"Sqreen"}]}])");

        EXPECT_TRUE(add->processor.ranCache.at("1").first);
        EXPECT_EQ(add->processor.ranCache.at("1").second, add->processor.runCount);

        ddwaf_result_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestCacheReport)
{
    // NOTE: this test only works due to the order of the rules in the ruleset
    //Initialize a PowerWAF rule
    auto rule = readFile("processor3.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param1 = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param1, "param1", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param1, &ret, LONG_TIME), DDWAF_MONITOR);
        EXPECT_EQ(ret.action, DDWAF_MONITOR);
        EXPECT_STREQ(ret.data, R"([{"ret_code":1,"flow":"flow1","rule":"1","filter":[{"operator":"match_regex","operator_value":"Sqreen","binding_accessor":"param1","manifest_key":"param1","resolved_value":"Sqreen","match_status":"Sqreen"}]}])");

        ddwaf_result_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "Pony"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_GOOD);
        EXPECT_EQ(ret.action, DDWAF_GOOD);
        EXPECT_EQ(ret.data, nullptr);

        ddwaf_result_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param2", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MONITOR);
        EXPECT_EQ(ret.action, DDWAF_MONITOR);
        EXPECT_STREQ(ret.data, R"([{"ret_code":1,"flow":"flow1","rule":"2","filter":[{"operator":"match_regex","operator_value":"Sqreen","binding_accessor":"param2","manifest_key":"param2","resolved_value":"Sqreen","match_status":"Sqreen"}]}])");

        ddwaf_result_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestMultiFlowCacheReport)
{
    //Initialize a PowerWAF rule
    auto rule = readFile("processor4.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param1", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MONITOR);
        EXPECT_EQ(ret.action, DDWAF_MONITOR);
        EXPECT_STREQ(ret.data, R"([{"ret_code":1,"flow":"flow1","rule":"1","filter":[{"operator":"match_regex","operator_value":"Sqreen","binding_accessor":"param1","manifest_key":"param1","resolved_value":"Sqreen","match_status":"Sqreen"}]}])");

        ddwaf_result_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "Pony"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_GOOD);
        EXPECT_EQ(ret.action, DDWAF_GOOD);
        EXPECT_EQ(ret.data, nullptr);

        ddwaf_result_free(&ret);
    }

    {
        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "param2", ddwaf_object_string(&tmp, "Sqreen"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MONITOR);
        EXPECT_EQ(ret.action, DDWAF_MONITOR);
        EXPECT_STREQ(ret.data, R"([{"ret_code":1,"flow":"flow2","rule":"2","filter":[{"operator":"match_regex","operator_value":"Sqreen","binding_accessor":"param2","manifest_key":"param2","resolved_value":"Sqreen","match_status":"Sqreen"}]}])");

        ddwaf_result_free(&ret);
    }

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestBudget)
{
    //Initialize a PowerWAF rule
    auto rule = readFile("slow.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    //Generate a wrapper
    ddwaf_object param = DDWAF_OBJECT_MAP, mapItem = DDWAF_OBJECT_ARRAY, array = DDWAF_OBJECT_ARRAY, tmp;

    for (int i = 0; i < 500; ++i)
    {
        ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "abbbbbbbbbabababababababaaaaaaaaaaaaaad"));
    }

    ddwaf_object_array_add(&mapItem, &array);
    ddwaf_object_map_add(&param, "rx_param", &mapItem);

    PowerWAF* waf = reinterpret_cast<PowerWAF*>(handle);
    PWRetriever wrapper(waf->manifest, DDWAF_MAX_MAP_DEPTH, 500);
    wrapper.addParameter(param);
    ASSERT_TRUE(wrapper.isValid());

    //Fetch the rule and flow managers
    auto& flows                      = waf->flows;
    const PWRuleManager& ruleManager = waf->ruleManager;

    rapidjson::Document document;
    PWRetManager rManager(TIME_STORE_DEFAULT, document.GetAllocator());
    PWProcessor processor(wrapper, ruleManager);
    processor.startNewRun(SQPowerWAF::monotonic_clock::now() + chrono::microseconds(50));

    processor.runFlow("flow1", flows["flow1"], rManager);
    ddwaf_result ret = rManager.synthetize();

    std::string result = std::string(ret.data).substr(0, strlen(R"([{"ret_code":-1,"flow":"flow1")"));

    EXPECT_STREQ(result.c_str(), R"([{"ret_code":-1,"flow":"flow1")");

    mapItem.parameterName = NULL;

    ddwaf_object_free(&param);
    ddwaf_result_free(&ret);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestBudgetRules)
{
    //Initialize a PowerWAF rule
    auto rule = readFile("slow.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&param, "param", ddwaf_object_string(&tmp, "aaaabbbbbaaa"));

    EXPECT_EQ(ddwaf_run(context, &param, &ret, 50), DDWAF_GOOD);
    EXPECT_EQ(ret.action, DDWAF_GOOD);
    EXPECT_TRUE(!strncmp(ret.data, R"([{"ret_code":-1,"flow":"flow1")", strlen(R"([{"ret_code":-1,"flow":"flow1")")));

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestPerfReporting)
{
    int countRXRecords = 0;
    auto runTest       = [&]() {
        ddwaf_config config = { 0, 0, 6 };

        //Initialize a PowerWAF rule
        auto rule = readFile("slow.yaml");
        ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

        ddwaf_handle handle = ddwaf_init(&rule, &config);
        ASSERT_NE(handle, nullptr);
        ddwaf_object_free(&rule);

        ddwaf_result ret;
        ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
        ASSERT_NE(context, nullptr);

        ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object_map_add(&param, "rx_param", ddwaf_object_string(&tmp, "aaaabbbbbaaa"));
        ddwaf_object_map_add(&param, "pm_param", ddwaf_object_string(&tmp, "something"));

        EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_GOOD);
        EXPECT_EQ(ret.action, DDWAF_GOOD);
        EXPECT_EQ(ret.data, nullptr);
        ASSERT_NE(ret.perfData, nullptr);

        {
            rapidjson::Document doc;
            doc.Parse(ret.perfData);

            ASSERT_TRUE(doc.IsObject());
            ASSERT_TRUE(OBJ_HAS_KEY_AS_ARRAY(doc, "topRuleRuntime"));

            auto array = doc["topRuleRuntime"].GetArray();
            EXPECT_EQ(array.Size(), 6);

            countRXRecords = 0;
            for (const auto& item : array)
            {
                ASSERT_TRUE(item.IsArray());
                ASSERT_EQ(item.Size(), 2);

                ASSERT_TRUE(item[0].IsString());
                countRXRecords += !strncmp(item[0].GetString(), "rx_", 3);

                ASSERT_TRUE(item[1].IsUint());
                EXPECT_NE(item[1].GetUint(), 0);
            }
        }
        ddwaf_result_free(&ret);
        ddwaf_context_destroy(context);
        ddwaf_destroy(handle);
    };

    for (int i = 0; i < 10; ++i)
    {
        runTest();
        if (countRXRecords >= 3)
            break;
    }

    EXPECT_GE(countRXRecords, 3);
}

TEST(TestPWProcessor, TestPerfReportingIncomplete)
{
    //Initialize a PowerWAF rule
    auto rule = readRule(R"({version: '2.1', rules: [{id: 1, tags: {type: bla}, conditions: [{operator: match_regex, parameters: {inputs: [{address: bla}], regex: pouet}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&param, "bla", ddwaf_object_string(&tmp, "pouet bla"));

    EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_MONITOR);
    EXPECT_EQ(ret.action, DDWAF_MONITOR);
    ASSERT_NE(ret.perfData, nullptr);

    {
        rapidjson::Document doc;
        doc.Parse(ret.perfData);

        ASSERT_TRUE(doc.IsObject());
        ASSERT_TRUE(OBJ_HAS_KEY_AS_ARRAY(doc, "topRuleRuntime"));

        auto array = doc["topRuleRuntime"].GetArray();
        EXPECT_EQ(array.Size(), 1);

        for (const auto& item : array)
        {
            ASSERT_TRUE(item.IsArray());
            ASSERT_EQ(item.Size(), 2);

            ASSERT_TRUE(item[0].IsString());
            EXPECT_STREQ(item[0].GetString(), "1");

            ASSERT_TRUE(item[1].IsUint());
            EXPECT_NE(item[1].GetUint(), 0);
        }
    }

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestPWProcessor, TestDisablePerfReporting)
{
    ddwaf_config config = { 0, 0, 0 };

    //Initialize a PowerWAF rule
    auto rule = readRule(R"({version: '2.1', rules: [{id: 1, tags: {type: bla}, conditions: [{operator: match_regex, parameters: {inputs: [{address: bla}], regex: pouet}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, &config);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_result ret;
    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    ddwaf_object param = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&param, "bla", ddwaf_object_string(&tmp, "aaaabbbbbaaa"));

    EXPECT_EQ(ddwaf_run(context, &param, &ret, LONG_TIME), DDWAF_GOOD);
    EXPECT_EQ(ret.action, DDWAF_GOOD);
    EXPECT_EQ(ret.perfData, nullptr);

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
