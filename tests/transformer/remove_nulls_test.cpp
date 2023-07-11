// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include <transformer/remove_nulls.hpp>

TEST(TestRemoveNulls, NameAndID)
{
    EXPECT_STREQ(transformer::remove_nulls::name().data(), "remove_nulls");
    EXPECT_EQ(transformer::remove_nulls::id(), transformer_id::remove_nulls);
}

TEST(TestRemoveNulls, EmptyString)
{
    lazy_string str("");
    EXPECT_FALSE(transformer::remove_nulls::transform(str));
    EXPECT_FALSE(str.modified());
}

TEST(TestRemoveNulls, ValidTransform)
{
    {
        lazy_string str({"r\0", sizeof("r\0") - 1});
        EXPECT_TRUE(transformer::remove_nulls::transform(str));
        EXPECT_STREQ(str.data(), "r");
    }

    {
        lazy_string str({"re\0", sizeof("re\0") - 1});
        EXPECT_TRUE(transformer::remove_nulls::transform(str));
        EXPECT_STREQ(str.data(), "re");
    }

    {
        lazy_string str({"\0re", sizeof("\0re") - 1});
        EXPECT_TRUE(transformer::remove_nulls::transform(str));
        EXPECT_STREQ(str.data(), "re");
    }

    {
        lazy_string str({"r\0e", sizeof("r\0e") - 1});
        EXPECT_TRUE(transformer::remove_nulls::transform(str));
        EXPECT_STREQ(str.data(), "re");
    }

    {
        lazy_string str({"removenulls\0", sizeof("removenulls\0") - 1});
        EXPECT_TRUE(transformer::remove_nulls::transform(str));
        EXPECT_STREQ(str.data(), "removenulls");
    }

    {
        lazy_string str({"remove\0nulls", sizeof("remove\0nulls") - 1});
        EXPECT_TRUE(transformer::remove_nulls::transform(str));
        EXPECT_STREQ(str.data(), "removenulls");
    }

    {
        lazy_string str({"\0removenulls", sizeof("\0removenulls") - 1});
        EXPECT_TRUE(transformer::remove_nulls::transform(str));
        EXPECT_STREQ(str.data(), "removenulls");
    }
}

TEST(TestRemoveNulls, InvalidTransform)
{
    {
        lazy_string str("r");
        EXPECT_FALSE(transformer::remove_nulls::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("rs");
        EXPECT_FALSE(transformer::remove_nulls::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("remove_nulls");
        EXPECT_FALSE(transformer::remove_nulls::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("remove_nulls but it doesn't matter");
        EXPECT_FALSE(transformer::remove_nulls::transform(str));
        EXPECT_FALSE(str.modified());
    }
}
