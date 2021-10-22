// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

DDWAF_RET_CODE getCodeForRun(ddwaf_result input)
{
    auto output = input.action;
    ddwaf_result_free(&input);
    return output;
}

TEST(FunctionalTests, ddwaf_run)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle1 = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    rule = readFile("interface2.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&rule);

    // Should block due to flow1 in rule1, not in rule2
    {
        ddwaf_context context1 = ddwaf_context_init(handle1, NULL);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2, NULL);
        ASSERT_NE(context2, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_key = DDWAF_OBJECT_ARRAY, param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_array_add(&param_key, ddwaf_object_unsigned(&tmp, 4242));
        ddwaf_object_array_add(&param_key, ddwaf_object_string(&tmp, "randomString"));

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));

        ddwaf_object_map_add(&parameter, "value1", &param_key);
        ddwaf_object_map_add(&parameter, "value2", &param_val);

        EXPECT_EQ(ddwaf_run(context1, &parameter, NULL, LONG_TIME), DDWAF_MONITOR);
        EXPECT_EQ(ddwaf_run(context2, &parameter, NULL, LONG_TIME), DDWAF_GOOD);

        ddwaf_object_free(&parameter);
        ddwaf_context_destroy(context1);
        ddwaf_context_destroy(context2);
    }

    // Shouldn't block
    {
        ddwaf_context context1 = ddwaf_context_init(handle1, NULL);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2, NULL);
        ASSERT_NE(context2, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_key = DDWAF_OBJECT_ARRAY, param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_array_add(&param_key, ddwaf_object_unsigned(&tmp, 4242));
        ddwaf_object_array_add(&param_key, ddwaf_object_string(&tmp, "randomString"));

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "randomString"));

        ddwaf_object_map_add(&parameter, "value1", &param_key);
        ddwaf_object_map_add(&parameter, "value2", &param_val);

        EXPECT_EQ(ddwaf_run(context1, &parameter, NULL, LONG_TIME), DDWAF_GOOD);
        EXPECT_EQ(ddwaf_run(context2, &parameter, NULL, LONG_TIME), DDWAF_GOOD);

        ddwaf_object_free(&parameter);
        ddwaf_context_destroy(context1);
        ddwaf_context_destroy(context2);
    }

    // Should monitor due to flow 2
    {
        ddwaf_context context1 = ddwaf_context_init(handle1, NULL);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2, NULL);
        ASSERT_NE(context2, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_key = DDWAF_OBJECT_ARRAY, param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_array_add(&param_key, ddwaf_object_unsigned(&tmp, 4242));
        ddwaf_object_array_add(&param_key, ddwaf_object_string(&tmp, "randomString"));

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule2"));

        ddwaf_object_map_add(&parameter, "value2", &param_key);
        ddwaf_object_map_add(&parameter, "value1", &param_val);

        EXPECT_EQ(ddwaf_run(context1, &parameter, NULL, LONG_TIME), DDWAF_MONITOR);
        EXPECT_EQ(ddwaf_run(context2, &parameter, NULL, LONG_TIME), DDWAF_GOOD);

        ddwaf_object_free(&parameter);
        ddwaf_context_destroy(context1);
        ddwaf_context_destroy(context2);
    }

    // Should monitor due to both conditions of flow 2 being met, thus also triggering rule2
    {
        ddwaf_context context1 = ddwaf_context_init(handle1, NULL);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2, NULL);
        ASSERT_NE(context2, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_key = DDWAF_OBJECT_MAP, param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_map_add(&param_key, "derp", ddwaf_object_unsigned(&tmp, 4242));
        ddwaf_object_map_add(&param_key, "bla", ddwaf_object_string(&tmp, "rule3"));

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule2"));

        ddwaf_object_map_add(&parameter, "value2", &param_key);
        ddwaf_object_map_add(&parameter, "value1", &param_val);

        EXPECT_EQ(ddwaf_run(context1, &parameter, NULL, LONG_TIME), DDWAF_MONITOR);
        EXPECT_EQ(ddwaf_run(context2, &parameter, NULL, LONG_TIME), DDWAF_MONITOR);

        ddwaf_object_free(&parameter);
        ddwaf_context_destroy(context1);
        ddwaf_context_destroy(context2);
    }

    // Should monitor due to the second condition flow 2
    {
        ddwaf_context context1 = ddwaf_context_init(handle1, NULL);
        ASSERT_NE(context1, nullptr);

        ddwaf_context context2 = ddwaf_context_init(handle2, NULL);
        ASSERT_NE(context2, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_key = DDWAF_OBJECT_MAP, param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_map_add(&param_key, "derp", ddwaf_object_unsigned(&tmp, 4242));
        ddwaf_object_map_add(&param_key, "bla", ddwaf_object_string(&tmp, "rule3"));

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "randomString"));

        ddwaf_object_map_add(&parameter, "value2", &param_key);
        ddwaf_object_map_add(&parameter, "value3", &param_val);

        EXPECT_EQ(ddwaf_run(context1, &parameter, NULL, LONG_TIME), DDWAF_MONITOR);
        EXPECT_EQ(ddwaf_run(context2, &parameter, NULL, LONG_TIME), DDWAF_GOOD);

        ddwaf_object_free(&parameter);
        ddwaf_context_destroy(context1);
        ddwaf_context_destroy(context2);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
}

TEST(FunctionalTests, HandleGood)
{
    auto rule = readFile("interface2.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    const ddwaf_handle handle = ddwaf_init(&rule, NULL);
    ddwaf_object_free(&rule);

    ASSERT_NE(handle, nullptr);

    // Should monitor due to both conditions of flow 2 being met, thus also triggering rule2
    {
        ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
        ASSERT_NE(context, nullptr);

        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_key = DDWAF_OBJECT_MAP, param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_map_add(&param_key, "derp", ddwaf_object_unsigned(&tmp, 4242));
        ddwaf_object_map_add(&param_key, "bla", ddwaf_object_string(&tmp, "rule3"));

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule2"));

        ddwaf_object_map_add(&parameter, "value2", &param_key);
        ddwaf_object_map_add(&parameter, "value1", &param_val);

        ddwaf_result ret;
        EXPECT_EQ(ddwaf_run(context, &parameter, &ret, LONG_TIME), DDWAF_MONITOR);

        EXPECT_EQ(DDWAF_MONITOR, ret.action);
        EXPECT_STREQ(ret.data, R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"flow1","category":"category1"}},"rule_matches":[{"operator":"match_regex","operator_value":"rule2","parameters":[{"address":"value1","key_path":[0],"resolved_value":"rule2"}],"highlight":["rule2"]},{"operator":"match_regex","operator_value":"rule3","parameters":[{"address":"value2","key_path":["bla"],"resolved_value":"rule3"}],"highlight":["rule3"]}]}])");

        ddwaf_result_free(&ret);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(FunctionalTests, HandleBad)
{
    ddwaf_object tmp, object = DDWAF_OBJECT_INVALID;
    EXPECT_EQ(ddwaf_init(&object, nullptr), nullptr);

    EXPECT_NO_FATAL_FAILURE(ddwaf_destroy(nullptr));

    ddwaf_object_string(&object, "value");
    EXPECT_EQ(ddwaf_run(nullptr, &object, NULL, 1), DDWAF_ERR_INVALID_ARGUMENT);
    ddwaf_object_free(&object);

    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    ddwaf_object_string(&object, "value");
    EXPECT_EQ(ddwaf_run(context, &object, NULL, 1), DDWAF_ERR_INVALID_OBJECT);

    object = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&object, "value1", ddwaf_object_string(&tmp, "value"));
    EXPECT_EQ(ddwaf_run(context, &object, NULL, 0), DDWAF_ERR_TIMEOUT);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(FunctionalTests, Budget)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle1 = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle1, nullptr);
    ddwaf_object_free(&rule);

    rule = readFile("interface2.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle2 = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle2, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle1, NULL);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle2, NULL);
    ASSERT_NE(context2, nullptr);

    ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object param_key = DDWAF_OBJECT_MAP, param_val = DDWAF_OBJECT_ARRAY;

    ddwaf_object_map_add(&param_key, "derp", ddwaf_object_unsigned(&tmp, 4242));
    ddwaf_object_map_add(&param_key, "bla", ddwaf_object_string(&tmp, "rule3"));

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule2"));

    ddwaf_object_map_add(&parameter, "value2", &param_key);
    ddwaf_object_map_add(&parameter, "value1", &param_val);

    EXPECT_EQ(ddwaf_run(context1, &parameter, NULL, LONG_TIME), DDWAF_MONITOR);
    EXPECT_EQ(ddwaf_run(context2, &parameter, NULL, LONG_TIME), DDWAF_MONITOR);

    EXPECT_EQ(ddwaf_run(context1, &parameter, NULL, SHORT_TIME), DDWAF_GOOD);
    EXPECT_EQ(ddwaf_run(context2, &parameter, NULL, SHORT_TIME), DDWAF_GOOD);

    ddwaf_object_free(&parameter);

    ddwaf_context_destroy(context1);
    ddwaf_context_destroy(context2);

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
}

TEST(FunctionalTests, ddwaf_get_version)
{
    ddwaf_version version;
    ddwaf_get_version(&version);

    EXPECT_EQ(version.major, 1);
    EXPECT_EQ(version.minor, 0);
    EXPECT_EQ(version.patch, 13);
}

TEST(FunctionalTests, ddwaf_runNull)
{
    auto rule = readRule(R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: arachni_detection, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: bla}], regex: Arachni}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    const char lol[] = "\0Arachni\0";
    ddwaf_object map = DDWAF_OBJECT_MAP, string;
    ddwaf_object_map_add(&map, "bla", ddwaf_object_stringl(&string, lol, sizeof(lol) - 1));

    ddwaf_context context = ddwaf_context_init(handle, NULL);
    ASSERT_NE(context, nullptr);

    ddwaf_result out;
    EXPECT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MONITOR);
    EXPECT_EQ(out.action, DDWAF_MONITOR);
    EXPECT_STREQ(out.data, R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"arachni_detection","category":"category1"}},"rule_matches":[{"operator":"match_regex","operator_value":"Arachni","parameters":[{"address":"bla","key_path":[],"resolved_value":"\u0000Arachni\u0000"}],"highlight":["Arachni"]}]}])");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);

    ////Add a removeNull transformer
    rule = readRule(R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: arachni_detection, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: bla}], regex: Arachni}}], transformers: [removeNulls]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    context = ddwaf_context_init(handle, NULL);
    ASSERT_NE(context, nullptr);

    EXPECT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MONITOR);

    EXPECT_EQ(out.action, DDWAF_MONITOR);
    EXPECT_STREQ(out.data, R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"arachni_detection","category":"category1"}},"rule_matches":[{"operator":"match_regex","operator_value":"Arachni","parameters":[{"address":"bla","key_path":[],"resolved_value":"Arachni"}],"highlight":["Arachni"]}]}])");

    ddwaf_object_free(&map);
    ddwaf_result_free(&out);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
