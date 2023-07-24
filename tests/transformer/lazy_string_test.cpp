// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include <stdexcept>
#include <transformer/common/lazy_string.hpp>

TEST(TestLazyString, ConstRead)
{
    constexpr std::string_view original = "value";
    lazy_string str(original);

    EXPECT_EQ(original.length(), str.length());
    for (size_t i = 0; i < original.length(); ++i) { EXPECT_EQ(original[i], str.at(i)); }

    EXPECT_FALSE(str.modified());
    EXPECT_NE(str.data(), nullptr);
}

TEST(TestLazyString, NonConstRead)
{
    constexpr std::string_view original = "value";
    lazy_string str(original);

    EXPECT_EQ(original.length(), str.length());
    for (size_t i = 0; i < original.length(); ++i) { EXPECT_EQ(original[i], str[i]); }

    EXPECT_TRUE(str.modified());
    EXPECT_NE(str.data(), nullptr);
}

TEST(TestLazyString, WriteAndTruncate)
{
    lazy_string str("value");
    EXPECT_EQ(str.length(), 5);

    str[3] = 'e';
    EXPECT_TRUE(str.modified());
    EXPECT_NE(str.data(), nullptr);

    str.truncate(4);
    EXPECT_EQ(str.length(), 4);
    EXPECT_STREQ(str.data(), "vale");
}

TEST(TestLazyString, EmptyString)
{
    lazy_string str("");
    EXPECT_EQ(str.length(), 0);

    str.truncate(str.length());
    EXPECT_EQ(str.length(), 0);
    EXPECT_TRUE(str.modified());
    EXPECT_NE(str.data(), nullptr);
    EXPECT_STREQ(str.data(), "");
}

TEST(TestLazyString, NullString) { EXPECT_THROW(lazy_string({}), std::runtime_error); }

TEST(TestLazyString, MoveString)
{
    lazy_string str("value");
    EXPECT_EQ(str.length(), 5);

    str[3] = 'e';
    EXPECT_TRUE(str.modified());
    EXPECT_NE(str.data(), nullptr);

    auto [buffer, length] = str.move();
    EXPECT_STREQ(buffer, "valee");
    EXPECT_EQ(length, 5);
    free(buffer);

    EXPECT_EQ(str.length(), 0);
    EXPECT_FALSE(str.modified());
    EXPECT_EQ(str.data(), nullptr);
}
