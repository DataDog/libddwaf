// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include "transformer/remove_comments.hpp"
#include "transformer_utils.hpp"

TEST(TestRemoveComments, NameAndID)
{
    EXPECT_STREQ(transformer::remove_comments::name().data(), "remove_comments");
    EXPECT_EQ(transformer::remove_comments::id(), transformer_id::remove_comments);
}

TEST(TestRemoveComments, EmptyString) { EXPECT_NO_TRANSFORM(remove_comments, ""); }

TEST(TestRemoveComments, ValidTransformShellComment)
{
    EXPECT_TRANSFORM(remove_comments, "#", "");
    EXPECT_TRANSFORM(remove_comments, "#foo", "");
    EXPECT_TRANSFORM(remove_comments, "bar#foo", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar#", "bar");
}

TEST(TestRemoveComments, ValidTransformSQLComment)
{
    EXPECT_TRANSFORM(remove_comments, "--", "");
    EXPECT_TRANSFORM(remove_comments, "--foo", "");
    EXPECT_TRANSFORM(remove_comments, "bar--foo", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar--", "bar");
}

TEST(TestRemoveComments, ValidTransformCPPComment)
{
    EXPECT_TRANSFORM(remove_comments, "//", "");
    EXPECT_TRANSFORM(remove_comments, "//foo", "");
    EXPECT_TRANSFORM(remove_comments, "bar//foo", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar//", "bar");
}

TEST(TestRemoveComments, ValidTransformHTMLComment)
{
    EXPECT_TRANSFORM(remove_comments, "<!--foo-->", "");
    EXPECT_TRANSFORM(remove_comments, "<!--foo-->bar", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar<!--foo-->", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar<!--foo-->bar", "barbar");
    EXPECT_TRANSFORM(remove_comments, "bar<!--foo--><!--foo-->bar", "barbar");
    EXPECT_TRANSFORM(remove_comments, "bar<!--foo--><!--foo-->bar", "barbar");
    EXPECT_TRANSFORM(remove_comments, "bar<!--foo-->bar<!--foo-->bar", "barbarbar");
    // This is a strange case, out algorithm is quite simple and will
    // detect the final -->bar as an SQL comment
    EXPECT_TRANSFORM(remove_comments, "bar<!--<!--foo-->-->bar", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar<!--", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar<!--foo bar", "bar");
    EXPECT_TRANSFORM(remove_comments, "foo<!---->bar", "foobar");
}

TEST(TestRemoveComments, ValidTransformCComment)
{
    EXPECT_TRANSFORM(remove_comments, "/*foo*/", "");
    EXPECT_TRANSFORM(remove_comments, "/*foo*/bar", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar/*foo*/", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar/*foo*/bar", "barbar");
    EXPECT_TRANSFORM(remove_comments, "bar/*foo*//*foo*/bar", "barbar");
    EXPECT_TRANSFORM(remove_comments, "bar/*foo*//*foo*/bar", "barbar");
    EXPECT_TRANSFORM(remove_comments, "bar/*foo*/bar/*foo*/bar", "barbarbar");
    EXPECT_TRANSFORM(remove_comments, "bar/*/*foo*/*/bar", "bar*/bar");
    EXPECT_TRANSFORM(remove_comments, "bar/*", "bar");
    EXPECT_TRANSFORM(remove_comments, "bar/*foo bar", "bar");
    EXPECT_TRANSFORM(remove_comments, "foo/**/bar", "foobar");
}

TEST(TestRemoveComments, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(remove_comments, "-");
    EXPECT_NO_TRANSFORM(remove_comments, "/");
    EXPECT_NO_TRANSFORM(remove_comments, "<");
    EXPECT_NO_TRANSFORM(remove_comments, "<!");
    EXPECT_NO_TRANSFORM(remove_comments, "<!-");
    EXPECT_NO_TRANSFORM(remove_comments, "r");
    EXPECT_NO_TRANSFORM(remove_comments, "rc");
    EXPECT_NO_TRANSFORM(remove_comments, "remove_comments");
    EXPECT_NO_TRANSFORM(remove_comments, "remove_comments but it doesn't matter");
}
