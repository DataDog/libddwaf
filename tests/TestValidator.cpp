// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"


TEST(TestValidator, TestMalformedMasterParam)
{
    ddwaf::validator validator;

    ddwaf_object masterMap = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object_map_add(&masterMap, "value", ddwaf_object_unsigned_force(&tmp, 42));

    EXPECT_TRUE(validator.validate(masterMap));
    EXPECT_FALSE(validator.validate(DDWAF_OBJECT_INVALID));

    masterMap.type = DDWAF_OBJ_ARRAY;
    EXPECT_FALSE(validator.validate(masterMap));

    masterMap.type = DDWAF_OBJ_MAP;
    masterMap.nbEntries = 0;
    EXPECT_TRUE(validator.validate(masterMap));

    {
        auto backup = masterMap.array;

        masterMap.array = nullptr;
        EXPECT_TRUE(validator.validate(masterMap));

        masterMap.nbEntries = 1;
        EXPECT_FALSE(validator.validate(masterMap));

        masterMap.array = backup;
    }

    ddwaf_object_free(&masterMap);
}

TEST(TestValidator, TestMalformedUnsignedInt)
{
    ddwaf::validator validator;

    ddwaf_object param = DDWAF_OBJECT_UNSIGNED_FORCE(42);

    EXPECT_TRUE(validator.validate_helper(param));

    param.nbEntries = 1;
    EXPECT_FALSE(validator.validate_helper(param));
}

TEST(TestValidator, TestMalformedSignedInt)
{
    ddwaf::validator validator;

    ddwaf_object param = DDWAF_OBJECT_SIGNED_FORCE(42);

    EXPECT_TRUE(validator.validate_helper(param));

    param.nbEntries = 1;
    EXPECT_FALSE(validator.validate_helper(param));
}

TEST(TestValidator, TestMalformedString)
{
    ddwaf::validator validator;

    ddwaf_object param;
    ddwaf_object_string(&param, "Sqreen");

    EXPECT_TRUE(validator.validate_helper(param));

    param.nbEntries = 0;
    EXPECT_TRUE(validator.validate_helper(param));

    free((void*) param.array);
    param.array = nullptr;
    EXPECT_FALSE(validator.validate_helper(param));
}

TEST(TestValidator, TestMalformedMap)
{
    ddwaf::validator validator;

    ddwaf_object mapItem, param = DDWAF_OBJECT_MAP;
    ddwaf_object_string(&mapItem, "Sqreen");
    const char* string = "Sqreen";

    param.nbEntries             = 1;
    param.array                 = &mapItem;
    mapItem.parameterName       = string;
    mapItem.parameterNameLength = strlen(string);

    EXPECT_TRUE(validator.validate_helper(param));

    param.array = nullptr;
    EXPECT_FALSE(validator.validate_helper(param));
    param.array = &mapItem;

    param.nbEntries = 0;
    EXPECT_TRUE(validator.validate_helper(param));
    param.nbEntries = 1;

    mapItem.parameterName = nullptr;
    EXPECT_FALSE(validator.validate_helper(param));
    mapItem.parameterName = string;

    //Invalid subItem
    free((void*) mapItem.array);
    mapItem.array = NULL;

    EXPECT_FALSE(validator.validate_helper(param));
}

TEST(TestValidator, TestRecursiveMap)
{
    ddwaf::validator validator;

    ddwaf_object param;

    param.nbEntries     = 1;
    param.parameterName = "Sqreen";
    param.type          = DDWAF_OBJ_STRING;
    param.array         = &param;

    EXPECT_TRUE(validator.validate_helper(param));

    param.type = DDWAF_OBJ_MAP;
    EXPECT_FALSE(validator.validate_helper(param));
}

TEST(TestValidator, TestMalformedArray)
{
    ddwaf::validator validator;

    const char* string = "Sqreen";
    ddwaf_object param = DDWAF_OBJECT_ARRAY, mapItem = DDWAF_OBJECT_SIGNED_FORCE(42);

    param.nbEntries = 1;
    param.array     = &mapItem;

    EXPECT_TRUE(validator.validate_helper(param));

    param.array = nullptr;
    EXPECT_FALSE(validator.validate_helper(param));
    param.array = &mapItem;

    param.nbEntries = 0;
    EXPECT_TRUE(validator.validate_helper(param));
    param.nbEntries = 1;

    mapItem.parameterName = string;
    EXPECT_FALSE(validator.validate_helper(param));
    mapItem.parameterName = nullptr;

    //Invalid subItem
    mapItem.nbEntries = 1;
    EXPECT_FALSE(validator.validate_helper(param));
}

TEST(TestValidator, TestRecursiveArray)
{
    ddwaf::validator validator;

    ddwaf_object param = DDWAF_OBJECT_ARRAY;

    param.nbEntries = 1;
    param.array     = &param;
    EXPECT_FALSE(validator.validate_helper(param));

    param.type = DDWAF_OBJ_STRING;
    EXPECT_TRUE(validator.validate_helper(param));
}

TEST(TestValidator, TestInvalidType)
{
    ddwaf::validator validator;
    EXPECT_FALSE(validator.validate_helper(DDWAF_OBJECT_INVALID));
}

TEST(TestValidator, TestGetUnknownParameter)
{
    ddwaf::validator validator;
    ddwaf_object param = DDWAF_OBJECT_MAP, mapItem = DDWAF_OBJECT_SIGNED_FORCE(42);
    const char* string = "Sqreen";

    param.nbEntries             = 1;
    param.array                 = &mapItem;
    mapItem.parameterName       = string;
    mapItem.parameterNameLength = strlen(string);

    EXPECT_TRUE(validator.validate(param));
}

TEST(TestValidator, TestLimits)
{
    ddwaf_object param = DDWAF_OBJECT_MAP, mapItem = DDWAF_OBJECT_SIGNED_FORCE(42);
    const char* string = "Sqreen";

    param.nbEntries       = 1;
    param.array           = &mapItem;
    mapItem.parameterName = string;

    EXPECT_THROW(validator(0, 42), std::invalid_argument);
    EXPECT_THROW(validator(42, 0), std::invalid_argument);
    EXPECT_TRUE(validator(1, 1).validate(param));

    ddwaf_object array = DDWAF_OBJECT_ARRAY, tmp;

    for (int i = 0; i < 500; ++i)
    {
        ddwaf_object_array_add(&array, ddwaf_object_unsigned_force(&tmp, 42));
    }

    array.parameterName = string;
    param.array         = &array;
    EXPECT_FALSE(validator(1, 450).validate(param));
    EXPECT_TRUE(validator(1, 500).validate(param));

    ddwaf_object subArray = DDWAF_OBJECT_ARRAY;
    ddwaf_object_array_add(&subArray, ddwaf_object_unsigned_force(&tmp, 42));

    ddwaf_object_array_add(&array, &subArray);

    EXPECT_FALSE(validator(10, 500).validate(param));
    EXPECT_TRUE(validator(10, 501).validate(param));
    EXPECT_FALSE(validator(1, 501).validate(param));

    array.parameterName = 0;
    ddwaf_object_free(&array);
}
