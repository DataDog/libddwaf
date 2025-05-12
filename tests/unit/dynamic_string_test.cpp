// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <stdexcept>

#include <dynamic_string.hpp>

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestDynamicString, DefaultConstructor)
{
    dynamic_string str;

    // +1 for nul-character
    EXPECT_EQ(str.capacity(), 1);

    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_NE(str.data(), nullptr);
    EXPECT_STREQ(str.data(), "");
    EXPECT_STR(static_cast<std::string_view>(str), "");
    EXPECT_STR(static_cast<std::string>(str), "");
    EXPECT_EQ(str, str);
}

TEST(TestDynamicString, PreallocatedConstructor)
{
    dynamic_string str{20};

    // +1 for nul-character
    EXPECT_EQ(str.capacity(), 21);

    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_NE(str.data(), nullptr);
    EXPECT_STREQ(str.data(), "");
    EXPECT_STR(static_cast<std::string_view>(str), "");
    EXPECT_STR(static_cast<std::string>(str), "");
    EXPECT_EQ(str, str);
}

TEST(TestDynamicString, StringViewConstructor)
{
    dynamic_string str{"thisisastring"sv};

    // +1 for nul-character
    EXPECT_EQ(str.capacity(), 14);

    EXPECT_EQ(str.size(), 13);
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.data(), nullptr);
    EXPECT_STREQ(str.data(), "thisisastring");
    EXPECT_STR(static_cast<std::string_view>(str), "thisisastring");
    EXPECT_STR(static_cast<std::string>(str), "thisisastring");
    EXPECT_EQ(str, str);
}

TEST(TestDynamicString, StringConstructor)
{
    dynamic_string str{"thisisastring"s};

    // +1 for nul-character
    EXPECT_EQ(str.capacity(), 14);

    EXPECT_EQ(str.size(), 13);
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.data(), nullptr);
    EXPECT_STREQ(str.data(), "thisisastring");
    EXPECT_STR(static_cast<std::string_view>(str), "thisisastring");
    EXPECT_STR(static_cast<std::string>(str), "thisisastring");
    EXPECT_EQ(str, str);
}

TEST(TestDynamicString, CstringConstructor)
{
    dynamic_string str{"thisisastring"};

    // +1 for nul-character
    EXPECT_EQ(str.capacity(), 14);

    EXPECT_EQ(str.size(), 13);
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.data(), nullptr);
    EXPECT_STREQ(str.data(), "thisisastring");
    EXPECT_STR(static_cast<std::string_view>(str), "thisisastring");
    EXPECT_STR(static_cast<std::string>(str), "thisisastring");
    EXPECT_EQ(str, str);
}

TEST(TestDynamicString, CopyConstructor)
{
    dynamic_string str{"thisisastring"sv};
    EXPECT_NE(str.data(), nullptr);

    // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
    dynamic_string copy{str};
    EXPECT_NE(copy.data(), nullptr);
    EXPECT_NE(str.data(), copy.data());
    EXPECT_STREQ(str.data(), "thisisastring");
    EXPECT_STREQ(copy.data(), "thisisastring");
    EXPECT_EQ(str, copy);
}

TEST(TestDynamicString, CopyAssignment)
{
    dynamic_string str{"thisisastring"sv};
    EXPECT_NE(str.data(), nullptr);

    dynamic_string copy;
    EXPECT_NE(copy.data(), nullptr);

    copy = str;
    EXPECT_NE(str.data(), copy.data());
    EXPECT_STREQ(str.data(), "thisisastring");
    EXPECT_STREQ(copy.data(), "thisisastring");
    EXPECT_EQ(str, copy);
}

TEST(TestDynamicString, MoveConstructor)
{
    dynamic_string str{"thisisastring"sv};
    EXPECT_NE(str.data(), nullptr);

    // A move completely invalidates the original string
    // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
    dynamic_string copy{std::move(str)};
    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.data(), nullptr);

    EXPECT_NE(copy.data(), nullptr);
    EXPECT_NE(str.data(), copy.data());
    EXPECT_STREQ(copy.data(), "thisisastring");
    EXPECT_EQ(copy, copy);
}

TEST(TestDynamicString, MoveAssignment)
{
    dynamic_string str{"thisisastring"sv};
    EXPECT_NE(str.data(), nullptr);

    dynamic_string copy;
    EXPECT_NE(copy.data(), nullptr);

    copy = std::move(str);
    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.data(), nullptr);

    EXPECT_NE(copy.data(), nullptr);
    EXPECT_NE(str.data(), copy.data());
    EXPECT_STREQ(copy.data(), "thisisastring");
    EXPECT_EQ(copy, copy);
}

TEST(TestDynamicString, MoveToObject)
{
    dynamic_string str{"thisisastring"sv};
    EXPECT_NE(str.data(), nullptr);

    auto object = str.move();

    std::size_t length;
    const char *cstr = ddwaf_object_get_string(&object, &length);

    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.data(), nullptr);

    EXPECT_NE(cstr, nullptr);
    EXPECT_STREQ(cstr, "thisisastring");
    EXPECT_EQ(length, 13);

    ddwaf_object_free(&object);
}

TEST(TestDynamicString, AppendDefaultString)
{
    dynamic_string str;

    // +1 for nul-character
    EXPECT_EQ(str.capacity(), 1);
    EXPECT_EQ(str.size(), 0);
    EXPECT_STREQ(str.data(), "");

    str.append('c');
    EXPECT_GT(str.capacity(), 2);
    EXPECT_EQ(str.size(), 1);
    EXPECT_STREQ(str.data(), "c");

    str.append("string");
    EXPECT_GT(str.capacity(), 8);
    EXPECT_EQ(str.size(), 7);
    EXPECT_STREQ(str.data(), "cstring");
}

TEST(TestDynamicString, AppendPreallocatedString)
{
    dynamic_string str{20};

    // +1 for nul-character
    EXPECT_EQ(str.capacity(), 21);
    EXPECT_EQ(str.size(), 0);
    EXPECT_STREQ(str.data(), "");

    str.append('c');
    EXPECT_EQ(str.capacity(), 21);
    EXPECT_EQ(str.size(), 1);
    EXPECT_STREQ(str.data(), "c");

    str.append("string");
    EXPECT_EQ(str.capacity(), 21);
    EXPECT_EQ(str.size(), 7);
    EXPECT_STREQ(str.data(), "cstring");
}

TEST(TestDynamicString, AppendCharsAndStrings)
{
    dynamic_string str;

    // +1 for nul-character
    EXPECT_EQ(str.capacity(), 1);
    EXPECT_EQ(str.size(), 0);
    EXPECT_STREQ(str.data(), "");

    str.append("this");
    str.append(' ');
    str.append('i');
    str.append('s');
    str.append(" a string");
    str.append(' ');
    str.append("that");
    str.append(" has");
    str.append(' ');
    str.append("been appended");
    str.append(' ');
    str.append('h');
    str.append("ere");

    EXPECT_EQ(str.size(), 44);
    EXPECT_STREQ(str.data(), "this is a string that has been appended here");
}

TEST(TestDynamicString, Equality)
{
    dynamic_string hello{"hello"};
    dynamic_string bye{"bye"};

    EXPECT_NE(hello, bye);
    EXPECT_EQ(hello, hello);
    EXPECT_EQ(bye, bye);

    dynamic_string hello2{"hello"};
    EXPECT_NE(hello.data(), hello2.data());
    EXPECT_EQ(hello, hello2);
    EXPECT_EQ(hello2, hello);

    dynamic_string hello_plus{"hello is just a substring"};
    EXPECT_NE(hello, hello_plus);
    EXPECT_NE(hello_plus, hello);
}

} // namespace
