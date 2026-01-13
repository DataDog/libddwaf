// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cow_string.hpp>
#include <stdexcept>

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestCoWString, ConstRead)
{
    constexpr std::string_view original = "value";
    cow_string str(original);
    EXPECT_FALSE(str.modified());

    EXPECT_EQ(original.length(), str.length());
    for (size_t i = 0; i < original.length(); ++i) { EXPECT_EQ(original[i], str.at(i)); }

    EXPECT_FALSE(str.modified());
    EXPECT_NE(str.data(), nullptr);
}

TEST(TestCoWString, NonConstRead)
{
    constexpr std::string_view original = "value";
    cow_string str(original);
    EXPECT_FALSE(str.modified());

    EXPECT_EQ(original.length(), str.length());
    for (size_t i = 0; i < original.length(); ++i) { EXPECT_EQ(original[i], str[i]); }

    EXPECT_TRUE(str.modified());
    EXPECT_NE(str.data(), nullptr);
}

TEST(TestCoWString, TruncateUnmodified)
{
    cow_string str("value");
    EXPECT_EQ(str.length(), 5);
    EXPECT_FALSE(str.modified());

    str.truncate(4);

    EXPECT_EQ(str.length(), 4);
    EXPECT_STR(str, "valu");
}

TEST(TestCoWString, WriteAndTruncate)
{
    cow_string str("value");
    EXPECT_EQ(str.length(), 5);
    EXPECT_FALSE(str.modified());

    str[3] = 'e';
    EXPECT_TRUE(str.modified());
    EXPECT_NE(str.data(), nullptr);

    str.truncate(4);
    EXPECT_EQ(str.length(), 4);
    EXPECT_STR(str, "vale");
}

TEST(TestCoWString, EmptyString)
{
    cow_string str("");
    EXPECT_EQ(str.length(), 0);
    EXPECT_FALSE(str.modified());

    str.truncate(str.length());
    EXPECT_EQ(str.length(), 0);
    EXPECT_FALSE(str.modified());
    EXPECT_EQ(str.data(), nullptr);
    EXPECT_STR(str, "");
}

TEST(TestCoWString, NullString) { EXPECT_THROW(cow_string({}), std::runtime_error); }

TEST(TestCoWString, WriteAndMove)
{
    cow_string str("value");
    EXPECT_EQ(str.length(), 5);
    EXPECT_FALSE(str.modified());

    str[3] = 'e';
    EXPECT_TRUE(str.modified());
    EXPECT_NE(str.data(), nullptr);

    auto dstr = static_cast<dynamic_string>(str);
    EXPECT_STR(dstr, "valee");
    EXPECT_EQ(dstr.size(), 5);

    EXPECT_EQ(str.length(), 0);
    EXPECT_FALSE(str.modified());
    EXPECT_EQ(str.data(), nullptr);
}

TEST(TestCoWString, MoveUnmodified)
{
    cow_string str("value");
    EXPECT_EQ(str.length(), 5);
    EXPECT_FALSE(str.modified());

    auto dstr = static_cast<dynamic_string>(str);
    EXPECT_STR(dstr, "value");
    EXPECT_EQ(dstr.size(), 5);

    EXPECT_EQ(str.length(), 0);
    EXPECT_FALSE(str.modified());
    EXPECT_EQ(str.data(), nullptr);
}

TEST(TestCoWString, MoveAfterTruncate)
{
    cow_string str("value");
    EXPECT_EQ(str.length(), 5);
    EXPECT_FALSE(str.modified());

    str.truncate(4);

    auto dstr = static_cast<dynamic_string>(str);
    EXPECT_STR(dstr, "valu");
    EXPECT_EQ(dstr.size(), 4);

    EXPECT_EQ(str.length(), 0);
    EXPECT_FALSE(str.modified());
    EXPECT_EQ(str.data(), nullptr);
}

} // namespace
