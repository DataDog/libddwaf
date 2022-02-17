// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

bool tryInitializeRetriver(ddwaf_object input, uint32_t map = DDWAF_MAX_MAP_DEPTH, uint32_t array = DDWAF_MAX_ARRAY_LENGTH)
{
    PWManifest manifest;
    PWRetriever retriever(manifest, map, array);
    return retriever.wrapper.addParameter(input);
}

void populateManifest(PWManifest& manifest)
{
    for (auto key : { "value", "key", "mixed", "mixed2" })
    {
        manifest.insert(key, PWManifest::ArgDetails(key, PWT_VALUES_ONLY));
    }
}

TEST(TestPWArgsWrapper, TestMalformedMasterParam)
{
    PWManifest manifest;
    populateManifest(manifest);

    ddwaf_object masterMap = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&masterMap, "value", ddwaf_object_unsigned_force(&tmp, 42));

    EXPECT_TRUE(tryInitializeRetriver(masterMap));
    EXPECT_FALSE(tryInitializeRetriver(DDWAF_OBJECT_INVALID));

    masterMap.type = DDWAF_OBJ_ARRAY;
    EXPECT_FALSE(tryInitializeRetriver(masterMap));
    masterMap.type = DDWAF_OBJ_MAP;

    masterMap.nbEntries = 0;
    EXPECT_TRUE(PWRetriever(manifest, DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH).addParameter(masterMap));

    {
        auto backup = masterMap.array;

        masterMap.array = nullptr;
        EXPECT_TRUE(PWRetriever(manifest, DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH).addParameter(masterMap));

        masterMap.nbEntries = 1;
        EXPECT_FALSE(tryInitializeRetriver(masterMap));

        masterMap.array = backup;
    }

    ddwaf_object_free(&masterMap);
}

TEST(TestPWArgsWrapper, TestMalformedUnsignedInt)
{
    ddwaf_object param = DDWAF_OBJECT_UNSIGNED_FORCE(42);

    PWRetriever::PWArgsWrapper wrapper(DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH);

    EXPECT_TRUE(wrapper._validate_object(param, 0));

    param.nbEntries = 1;
    EXPECT_FALSE(wrapper._validate_object(param, 0));
}

TEST(TestPWArgsWrapper, TestMalformedSignedInt)
{
    ddwaf_object param = DDWAF_OBJECT_SIGNED_FORCE(42);

    PWRetriever::PWArgsWrapper wrapper(DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH);

    EXPECT_TRUE(wrapper._validate_object(param, 0));

    param.nbEntries = 1;
    EXPECT_FALSE(wrapper._validate_object(param, 0));
}

TEST(TestPWArgsWrapper, TestMalformedString)
{
    ddwaf_object param;
    ddwaf_object_string(&param, "Sqreen");

    PWRetriever::PWArgsWrapper wrapper(DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH);

    EXPECT_TRUE(wrapper._validate_object(param, 0));

    param.nbEntries = 0;
    EXPECT_TRUE(wrapper._validate_object(param, 0));

    free((void*) param.array);
    param.array = nullptr;
    EXPECT_FALSE(wrapper._validate_object(param, 0));
}

TEST(TestPWArgsWrapper, TestMalformedMap)
{
    PWRetriever::PWArgsWrapper wrapper(DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH);
    PWManifest manifest;
    populateManifest(manifest);

    ddwaf_object mapItem, param = DDWAF_OBJECT_MAP;
    ddwaf_object_string(&mapItem, "Sqreen");
    const char* string = "Sqreen";

    param.nbEntries             = 1;
    param.array                 = &mapItem;
    mapItem.parameterName       = string;
    mapItem.parameterNameLength = strlen(string);

    EXPECT_TRUE(wrapper._validate_object(param, 0));
    EXPECT_TRUE(tryInitializeRetriver(param));

    param.array = nullptr;
    EXPECT_FALSE(wrapper._validate_object(param, 0));
    EXPECT_FALSE(tryInitializeRetriver(param));
    param.array = &mapItem;

    param.nbEntries = 0;
    EXPECT_TRUE(wrapper._validate_object(param, 0));
    EXPECT_TRUE(PWRetriever(PWManifest(), DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH).addParameter(param));
    param.nbEntries = 1;

    mapItem.parameterName = nullptr;
    EXPECT_FALSE(wrapper._validate_object(param, 0));
    EXPECT_FALSE(tryInitializeRetriver(param));
    mapItem.parameterName = string;

    //Invalid subItem
    free((void*) mapItem.array);
    mapItem.array = NULL;

    EXPECT_FALSE(wrapper._validate_object(param, 0));
    EXPECT_FALSE(tryInitializeRetriver(param));
}

TEST(TestPWArgsWrapper, TestRecursiveMap)
{
    ddwaf_object param;

    param.nbEntries     = 1;
    param.parameterName = "Sqreen";
    param.type          = DDWAF_OBJ_STRING;
    param.array         = &param;

    PWRetriever::PWArgsWrapper wrapper(DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH);

    EXPECT_TRUE(wrapper._validate_object(param, 0));

    param.type = DDWAF_OBJ_MAP;
    EXPECT_FALSE(wrapper._validate_object(param, 0));
    EXPECT_FALSE(tryInitializeRetriver(param));
}

TEST(TestPWArgsWrapper, TestMalformedArray)
{
    const char* string = "Sqreen";
    ddwaf_object param = DDWAF_OBJECT_ARRAY, mapItem = DDWAF_OBJECT_SIGNED_FORCE(42);

    param.nbEntries = 1;
    param.array     = &mapItem;

    PWRetriever::PWArgsWrapper wrapper(DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH);

    EXPECT_TRUE(wrapper._validate_object(param, 0));

    param.array = nullptr;
    EXPECT_FALSE(wrapper._validate_object(param, 0));
    param.array = &mapItem;

    param.nbEntries = 0;
    EXPECT_TRUE(wrapper._validate_object(param, 0));
    param.nbEntries = 1;

    mapItem.parameterName = string;
    EXPECT_FALSE(wrapper._validate_object(param, 0));
    mapItem.parameterName = nullptr;

    //Invalid subItem
    mapItem.nbEntries = 1;
    EXPECT_FALSE(wrapper._validate_object(param, 0));
}

TEST(TestPWArgsWrapper, TestRecursiveArray)
{
    PWRetriever::PWArgsWrapper wrapper(DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH);

    ddwaf_object param = DDWAF_OBJECT_ARRAY;

    param.nbEntries = 1;
    param.array     = &param;
    EXPECT_FALSE(wrapper._validate_object(param, 0));

    param.type = DDWAF_OBJ_STRING;
    EXPECT_TRUE(wrapper._validate_object(param, 0));
}

TEST(TestPWArgsWrapper, TestInvalidType)
{
    PWRetriever::PWArgsWrapper wrapper(DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH);
    EXPECT_FALSE(wrapper._validate_object(DDWAF_OBJECT_INVALID, 0));
}

TEST(TestPWArgsWrapper, TestGetUnknownParameter)
{
    PWManifest manifest;
    ddwaf_object param = DDWAF_OBJECT_MAP, mapItem = DDWAF_OBJECT_SIGNED_FORCE(42);
    const char* string = "Sqreen";

    param.nbEntries             = 1;
    param.array                 = &mapItem;
    mapItem.parameterName       = string;
    mapItem.parameterNameLength = strlen(string);

    PWRetriever::PWArgsWrapper wrapper(DDWAF_MAX_MAP_DEPTH, DDWAF_MAX_ARRAY_LENGTH);

    ASSERT_TRUE(wrapper.addParameter(param));
    ASSERT_TRUE(wrapper.isValid());

    EXPECT_NE(wrapper.getParameter(string), nullptr);
    EXPECT_EQ(wrapper.getParameter("random name"), nullptr);
}

TEST(TestPWArgsWrapper, TestLimits)
{
    ddwaf_object param = DDWAF_OBJECT_MAP, mapItem = DDWAF_OBJECT_SIGNED_FORCE(42);
    const char* string = "Sqreen";

    param.nbEntries       = 1;
    param.array           = &mapItem;
    mapItem.parameterName = string;

    EXPECT_FALSE(tryInitializeRetriver(param, 0, 42));
    EXPECT_FALSE(tryInitializeRetriver(param, 42, 0));
    EXPECT_TRUE(tryInitializeRetriver(param, 1, 1));

    ddwaf_object array = DDWAF_OBJECT_ARRAY, tmp;

    for (int i = 0; i < 500; ++i)
    {
        ddwaf_object_array_add(&array, ddwaf_object_unsigned_force(&tmp, 42));
    }

    array.parameterName = string;
    param.array         = &array;
    EXPECT_FALSE(tryInitializeRetriver(param, 1, 450));
    EXPECT_TRUE(tryInitializeRetriver(param, 1, 500));

    ddwaf_object subArray = DDWAF_OBJECT_ARRAY;
    ddwaf_object_array_add(&subArray, ddwaf_object_unsigned_force(&tmp, 42));

    ddwaf_object_array_add(&array, &subArray);

    EXPECT_FALSE(tryInitializeRetriver(param, 10, 500));
    EXPECT_TRUE(tryInitializeRetriver(param, 10, 501));
    EXPECT_FALSE(tryInitializeRetriver(param, 1, 501));

    array.parameterName = 0;
    ddwaf_object_free(&array);
}
