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
    cow_string str("");
    EXPECT_FALSE(transformer::remove_comments::transform(str));
    EXPECT_FALSE(str.modified());
}

TEST(TestRemoveComments, ValidTransformShellComment)
{
    {
        cow_string str("#");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        cow_string str("#foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        cow_string str("bar#foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar#");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }
}

TEST(TestRemoveComments, ValidTransformSQLComment)
{
    {
        cow_string str("--");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        cow_string str("--foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        cow_string str("bar--foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar--");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }
}

TEST(TestRemoveComments, ValidTransformCPPComment)
{
    {
        cow_string str("//");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        cow_string str("//foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        cow_string str("bar//foo");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar//");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }
}

TEST(TestRemoveComments, ValidTransformHTMLComment)
{
    {
        cow_string str("<!--foo-->");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        cow_string str("<!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar<!--foo-->");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar<!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        cow_string str("bar<!--foo--><!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        cow_string str("bar<!--foo--><!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        cow_string str("bar<!--foo-->bar<!--foo-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbarbar");
    }

    {
        // This is a strange case, out algorithm is quite simple and will
        // detect the final -->bar as an SQL comment
        cow_string str("bar<!--<!--foo-->-->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar<!--");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar<!--foo bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("foo<!---->bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "foobar");
    }
}

TEST(TestRemoveComments, ValidTransformCComment)
{
    {
        cow_string str("/*foo*/");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "");
    }

    {
        cow_string str("/*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar/*foo*/");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar/*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        cow_string str("bar/*foo*//*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        cow_string str("bar/*foo*//*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbar");
    }

    {
        cow_string str("bar/*foo*/bar/*foo*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "barbarbar");
    }

    {
        cow_string str("bar/*/*foo*/*/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar*/bar");
    }

    {
        cow_string str("bar/*");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("bar/*foo bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "bar");
    }

    {
        cow_string str("foo/**/bar");
        EXPECT_TRUE(transformer::remove_comments::transform(str));
        EXPECT_STREQ(str.data(), "foobar");
    }
}

TEST(TestRemoveComments, InvalidTransform)
{
    {
        cow_string str("-");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("/");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("<");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("<!");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("<!-");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("r");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("rc");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("remove_comments");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }

    {
        cow_string str("remove_comments but it doesn't matter");
        EXPECT_FALSE(transformer::remove_comments::transform(str));
        EXPECT_FALSE(str.modified());
    }
}
