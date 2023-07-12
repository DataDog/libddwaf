// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/remove_comments.hpp"

TEST(TestRemoveComments, NameAndID)
{
    EXPECT_STREQ(transformer::remove_comments::name().data(), "remove_comments");
    EXPECT_EQ(transformer::remove_comments::id(), transformer_id::remove_comments);
}

TEST(TestRemoveComments, EmptyString)
{
    lazy_string str("");
    EXPECT_FALSE(transformer::remove_comments::transform(str));
    EXPECT_FALSE(str.modified());
}

TEST(TestRemoveComments, ValidTransformShellComment)
{
    {
        lazy_string str("#");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        lazy_string str("#foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        lazy_string str("bar#foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar#");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }
}

TEST(TestRemoveComments, ValidTransformSQLComment)
{
    {
        lazy_string str("--");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        lazy_string str("--foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        lazy_string str("bar--foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar--");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }
}

TEST(TestRemoveComments, ValidTransformCPPComment)
{
    {
        lazy_string str("//");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        lazy_string str("//foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        lazy_string str("bar//foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar//");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }
}

TEST(TestRemoveComments, ValidTransformHTMLComment)
{
    {
        lazy_string str("<!--foo-->");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        lazy_string str("<!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar<!--foo-->");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar<!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        lazy_string str("bar<!--foo--><!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        lazy_string str("bar<!--foo--><!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        lazy_string str("bar<!--foo-->bar<!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbarbar");
    }

    {
        // This is a strange case, out algorithm is quite simple and will
        // detect the final -->bar as an SQL comment
        lazy_string str("bar<!--<!--foo-->-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar<!--");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar<!--foo bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("foo<!---->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "foobar");
    }
}

TEST(TestRemoveComments, ValidTransformCComment)
{
    {
        lazy_string str("/*foo*/");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        lazy_string str("/*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar/*foo*/");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar/*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        lazy_string str("bar/*foo*//*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        lazy_string str("bar/*foo*//*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        lazy_string str("bar/*foo*/bar/*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbarbar");
    }

    {
        lazy_string str("bar/*/*foo*/*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar*/bar");
    }

    {
        lazy_string str("bar/*");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("bar/*foo bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        lazy_string str("foo/**/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "foobar");
    }
}

TEST(TestRemoveComments, InvalidTransform)
{
    {
        lazy_string str("-");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("/");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("<");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("<!");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("<!-");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("r");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("rc");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("remove_comments");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        lazy_string str("remove_comments but it doesn't matter");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }
}
