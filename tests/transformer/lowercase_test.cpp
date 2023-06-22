// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"

TEST(TestLowerCase, ValidTransform)
{
    lazy_string str("LoWeRCase");
    transformer::lowercase t;
    EXPECT_TRUE(t.transform(str));
    EXPECT_STREQ(str.get(), "lowercase");
}

TEST(TestLowerCase, InvalidTransform)
{
    lazy_string str("lowercase");
    transformer::lowercase t;
    EXPECT_FALSE(t.transform(str));
    EXPECT_STREQ(str.get(), nullptr);
}
