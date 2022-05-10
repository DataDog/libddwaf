// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestPWRetriever, TestCreateNoTarget)
{
    PWManifest manifest;
    PWRetriever retriever(manifest, ddwaf::object_limits{5, 5, 4096});

    Iterator& iterator = retriever.getIterator({});

    EXPECT_TRUE(iterator.isOver());
    EXPECT_EQ(iterator.argsIterator.state.activeItem, nullptr);
    EXPECT_FALSE(iterator.argsIterator.state.popStack());

    // Make sure this doesn't crash
    iterator.gotoNext();

    iterator.currentTargetRunOnKey = true;
    EXPECT_FALSE(iterator.shouldMatchKey());
}

TEST(TestPWRetriever, TestIterateInvalidItem)
{
    PWManifest manifest;
    PWRetriever retriever(manifest, ddwaf::object_limits{5, 5, 4096});
    vector<PWManifest::ARG_ID> targets = { 0 };

    Iterator& iterator = retriever.getIterator({});
    EXPECT_TRUE(iterator.isOver());

    ddwaf_object array = DDWAF_OBJECT_ARRAY, tmp;
    ddwaf_object_array_add(&array, ddwaf_object_signed_force(&tmp, 42));
    ddwaf_object_array_add(&array, ddwaf_object_signed_force(&tmp, 43));
    ddwaf_object_array_add(&array, ddwaf_object_signed_force(&tmp, 44));

    ((ddwaf_object*) array.array)[1].type = DDWAF_OBJ_INVALID;

    iterator.argsIterator.state.reset(&array);
    iterator.targetCursor = targets.cbegin();
    iterator.targetEnd    = targets.cend();

    ASSERT_NE(*iterator, nullptr);
    EXPECT_EQ((*iterator)->intValue, 42);
    EXPECT_FALSE(iterator.isOver());

    // Make sure we skip the illegal item
    iterator.gotoNext();

    ASSERT_NE(*iterator, nullptr);
    EXPECT_EQ((*iterator)->intValue, 44);

    ddwaf_object_free(&array);
}

TEST(TestPWRetriever, TestInvalidArgConstructor)
{
    ddwaf_object arg = DDWAF_OBJECT_INVALID;
    ArgsIterator argIter(&arg, 32);
    EXPECT_EQ(argIter.state.activeItem, nullptr);
}

TEST(TestPWRetriever, TestIterateEmptyArray)
{
    PWManifest manifest;
    PWRetriever retriever(manifest, ddwaf::object_limits{5, 5, 4096});
    vector<PWManifest::ARG_ID> targets = { 0 };

    Iterator& iterator = retriever.getIterator({});
    EXPECT_TRUE(iterator.isOver());

    ddwaf_object array = DDWAF_OBJECT_ARRAY, tmp;
    ddwaf_object_array_add(&array, ddwaf_object_signed_force(&tmp, 42));
    ddwaf_object_array_add(&array, ddwaf_object_signed_force(&tmp, 43));
    ddwaf_object_array_add(&array, ddwaf_object_signed_force(&tmp, 44));

    ((ddwaf_object*) array.array)[1].type      = DDWAF_OBJ_ARRAY;
    ((ddwaf_object*) array.array)[1].nbEntries = 0;
    ((ddwaf_object*) array.array)[1].array     = NULL;

    iterator.argsIterator.state.reset(&array);
    iterator.targetCursor = targets.cbegin();
    iterator.targetEnd    = targets.cend();

    ASSERT_NE(*iterator, nullptr);
    EXPECT_EQ((*iterator)->intValue, 42);
    EXPECT_FALSE(iterator.isOver());

    // Make sure we skip the illegal item
    iterator.gotoNext();

    ASSERT_NE(*iterator, nullptr);
    EXPECT_EQ((*iterator)->intValue, 44);

    ddwaf_object_free(&array);
}

TEST(TestPWRetriever, TestAccessSimplePath)
{
    auto rule = readFile("retriever.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);

    // Whitelist
    ddwaf_object topLevelMap = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&topLevelMap, "alpha", ddwaf_object_string(&tmp, "targeto"));
    ddwaf_object_map_add(&topLevelMap, "-1", ddwaf_object_string(&tmp, "target_bait2"));
    ddwaf_object_map_add(&topLevelMap, "a", ddwaf_object_string(&tmp, "real_target"));

    ddwaf_object paramHolder = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&paramHolder, "blob1", &topLevelMap);

    ddwaf_result ret;

    {
        ddwaf_context context = ddwaf_context_init(handle, nullptr);
        ASSERT_NE(context, nullptr);

        ASSERT_EQ(ddwaf_run(context, &paramHolder, &ret, LONG_TIME), DDWAF_MONITOR);
        EXPECT_FALSE(ret.timeout);
        EXPECT_STREQ(ret.data, R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"flow1","category":"category1"}},"rule_matches":[{"operator":"match_regex","operator_value":"target","parameters":[{"address":"blob1","key_path":["a"],"value":"real_target","highlight":["target"]}]}]}])");
        ddwaf_result_free(&ret);
        ddwaf_context_destroy(context);
    }

    ((char*) paramHolder.array[0].parameterName)[4] = '2';

    {
        ddwaf_context context = ddwaf_context_init(handle, nullptr);
        ASSERT_NE(context, nullptr);

        ASSERT_EQ(ddwaf_run(context, &paramHolder, &ret, LONG_TIME), DDWAF_MONITOR);
        EXPECT_FALSE(ret.timeout);
        EXPECT_STREQ(ret.data, R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"flow1","category":"category1"}},"rule_matches":[{"operator":"match_regex","operator_value":"target","parameters":[{"address":"blob2","key_path":["-1"],"value":"target_bait2","highlight":["target"]}]}]}])");
        ddwaf_result_free(&ret);
        ddwaf_context_destroy(context);
    }

    ((char*) paramHolder.array[0].parameterName)[4] = '3';

    {
        ddwaf_context context = ddwaf_context_init(handle, nullptr);
        ASSERT_NE(context, nullptr);

        ASSERT_EQ(ddwaf_run(context, &paramHolder, &ret, LONG_TIME), DDWAF_MONITOR);
        EXPECT_FALSE(ret.timeout);
        EXPECT_STREQ(ret.data, R"([{"rule":{"id":"1","name":"rule1","tags":{"type":"flow1","category":"category1"}},"rule_matches":[{"operator":"match_regex","operator_value":"target","parameters":[{"address":"blob3","key_path":["alpha"],"value":"targeto","highlight":["target"]}]}]}])");
        ddwaf_result_free(&ret);
        ddwaf_context_destroy(context);
    }

    ddwaf_object_free(&rule);
    ddwaf_object_free(&paramHolder);
    ddwaf_destroy(handle);
}

TEST(PWRetriever, NullErrorManagement)
{
    auto rule = readFile("retriever.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP, subMap = DDWAF_OBJECT_MAP, tmp;

    ddwaf_object_map_add(&subMap, "lol", ddwaf_object_string(&tmp, "bla"));
    ddwaf_object_map_add(&map, "blob", &subMap);

    PWRetriever retriever(((PowerWAF*) handle)->manifest);
    retriever.addParameter(map);

    rapidjson::Document document;
    ddwaf::obfuscator eo;
    PWRetManager rManager(eo);

    const condition& cond = ((PowerWAF*) handle)->rules[0].conditions.front();

    EXPECT_EQ(cond.performMatching(retriever, TIME_FAR, rManager), condition::status::missing_arg);

    ddwaf_object_free(&rule);
    ddwaf_object_free(&map);
    ddwaf_destroy(handle);
}

TEST(PWRetriever, IteratorAccessNull)
{
    auto rule = readFile("retriever.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP, subMap = DDWAF_OBJECT_MAP, tmp;

    ddwaf_object_map_add(&subMap, "lol", ddwaf_object_string(&tmp, "bla"));
    ddwaf_object_map_add(&map, "blob", &subMap);

    PWRetriever retriever(((PowerWAF*) handle)->manifest);
    retriever.addParameter(map);

    Iterator& iterator = retriever.getIterator({});

    EXPECT_EQ(*iterator, nullptr);

    ddwaf_object_free(&rule);
    ddwaf_object_free(&map);
    ddwaf_destroy(handle);
}

TEST(PWRetriever, IteratorBlockList)
{
    auto rule = readFile("retriever.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP, subMap = DDWAF_OBJECT_MAP, subSubMap = DDWAF_OBJECT_MAP, tmp;

    ddwaf_object_map_add(&subSubMap, "lol", ddwaf_object_string(&tmp, "bla"));
    ddwaf_object_map_add(&subSubMap, "lol2", ddwaf_object_string(&tmp, "bla2"));
    ddwaf_object_map_add(&subMap, "pouet", &subSubMap);
    ddwaf_object_map_add(&subMap, "a", ddwaf_object_string(&tmp, "bla3"));
    ddwaf_object_map_add(&map, "blob1", &subMap);

    PWRetriever retriever(((PowerWAF*) handle)->manifest);
    retriever.addParameter(map);

    const vector<PWManifest::ARG_ID> target = { 0 };
    Iterator& iterator         = retriever.getIterator(target);

    EXPECT_TRUE(iterator.moveIteratorForward(false));
    EXPECT_STREQ((*iterator)->stringValue, "bla3");

    ddwaf_object_free(&rule);
    ddwaf_object_free(&map);
    ddwaf_destroy(handle);
}

TEST(PWRetriever, KeyWithComplexStructure)
{
    auto rule = readFile("retriever.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    ddwaf_object parameter = DDWAF_OBJECT_MAP, value = DDWAF_OBJECT_ARRAY, tmp;
    ddwaf_object_array_add(&value, ddwaf_object_string(&tmp, "target"));

    ddwaf_object subMap = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&subMap, "bla", &value);

    ddwaf_object list = DDWAF_OBJECT_ARRAY;
    ddwaf_object_array_add(&list, &subMap);

    ddwaf_object_map_add(&parameter, "arg", &list);

    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, LONG_TIME), DDWAF_MONITOR);

    ddwaf_object_free(&rule);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
