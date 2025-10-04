// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <stdexcept>

#include <cow_string.hpp>
#include <dynamic_string.hpp>
#include <transformer/lowercase.hpp>

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestDynamicString, DefaultConstructor)
{
    dynamic_string str;

    EXPECT_EQ(str.capacity(), 0);

    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.data(), nullptr);
    EXPECT_EQ(str, str);
}

TEST(TestDynamicString, PreallocatedConstructor)
{
    dynamic_string str{20};

    EXPECT_EQ(str.capacity(), 20);

    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_NE(str.data(), nullptr);
    EXPECT_EQ(str, str);
}

TEST(TestDynamicString, StringViewConstructor)
{
    dynamic_string str{"thisisastring"sv};

    EXPECT_EQ(str.capacity(), 13);

    EXPECT_EQ(str.size(), 13);
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.data(), nullptr);
    EXPECT_STR(static_cast<std::string_view>(str), "thisisastring");
    EXPECT_STR(static_cast<std::string>(str), "thisisastring");
    EXPECT_EQ(str, str);
}

TEST(TestDynamicString, StringConstructor)
{
    dynamic_string str{"thisisastring"s};

    EXPECT_EQ(str.capacity(), 13);
    EXPECT_EQ(str.size(), 13);
    EXPECT_FALSE(str.empty());
    EXPECT_NE(str.data(), nullptr);
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
    EXPECT_STR(static_cast<std::string_view>(str), "thisisastring");
    EXPECT_STR(static_cast<std::string_view>(copy), "thisisastring");
    EXPECT_EQ(str, copy);
}

TEST(TestDynamicString, CopyAssignment)
{
    dynamic_string str{"thisisastring"sv};
    EXPECT_NE(str.data(), nullptr);

    dynamic_string copy;
    EXPECT_EQ(copy.data(), nullptr);

    copy = str;
    EXPECT_NE(str.data(), copy.data());
    EXPECT_STR(static_cast<std::string_view>(str), "thisisastring");
    EXPECT_STR(static_cast<std::string>(str), "thisisastring");
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
    EXPECT_STR(copy, "thisisastring");
    EXPECT_EQ(copy, copy);
}

TEST(TestDynamicString, MoveAssignment)
{
    dynamic_string str{"thisisastring"sv};
    EXPECT_NE(str.data(), nullptr);

    dynamic_string copy;
    EXPECT_EQ(copy.data(), nullptr);

    copy = std::move(str);
    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.data(), nullptr);

    EXPECT_NE(copy.data(), nullptr);
    EXPECT_NE(str.data(), copy.data());
    EXPECT_STR(copy, "thisisastring");
    EXPECT_EQ(copy, copy);
}

TEST(TestDynamicString, MoveToObject)
{
    dynamic_string str{"thisisastring"sv};
    EXPECT_NE(str.data(), nullptr);

    auto object = str.to_object();

    auto str_view = object.as<std::string_view>();

    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.data(), nullptr);

    EXPECT_NE(str_view.data(), nullptr);
    EXPECT_STR(str_view, "thisisastring");
}

TEST(TestDynamicString, MoveToObjectDifferentCapacity)
{
    dynamic_string str{32};
    str.append("thisisastring");
    EXPECT_NE(str.data(), nullptr);

    EXPECT_EQ(str.capacity(), 32);
    EXPECT_EQ(str.size(), 13);

    auto object = str.to_object();

    auto str_view = object.as<std::string_view>();

    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.data(), nullptr);

    EXPECT_NE(str_view.data(), nullptr);
    EXPECT_STR(str_view, "thisisastring");
}

TEST(TestDynamicString, MoveToObjectIncompatibleAllocatorAndDifferentCapacity)
{
    dynamic_string str{32};
    str.append("thisisnotasmallstring");
    EXPECT_NE(str.data(), nullptr);

    EXPECT_EQ(str.capacity(), 32);
    EXPECT_EQ(str.size(), 21);

    memory::monotonic_buffer_resource resource;
    auto object = str.to_object(&resource);
    EXPECT_EQ(object.alloc(), &resource);

    auto str_view = object.as<std::string_view>();

    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.data(), nullptr);

    EXPECT_NE(str_view.data(), nullptr);
    EXPECT_STR(str_view, "thisisnotasmallstring");
}

TEST(TestDynamicString, MoveToObjectIncompatibleAllocatorAnEqualCapacity)
{
    dynamic_string str{"thisisnotasmallstring"sv};
    EXPECT_NE(str.data(), nullptr);

    EXPECT_EQ(str.capacity(), 21);
    EXPECT_EQ(str.size(), 21);

    memory::monotonic_buffer_resource resource;
    auto object = str.to_object(&resource);
    EXPECT_EQ(object.alloc(), &resource);

    auto str_view = object.as<std::string_view>();

    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.data(), nullptr);

    EXPECT_NE(str_view.data(), nullptr);
    EXPECT_STR(str_view, "thisisnotasmallstring");
}

TEST(TestDynamicString, AppendDefaultString)
{
    dynamic_string str;

    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);
    EXPECT_STR(str, "");

    str.append('c');
    EXPECT_GE(str.capacity(), 1);
    EXPECT_EQ(str.size(), 1);
    EXPECT_STR(str, "c");

    str.append("string");
    EXPECT_GE(str.capacity(), 7);
    EXPECT_EQ(str.size(), 7);
    EXPECT_STR(str, "cstring");
}

TEST(TestDynamicString, AppendPreallocatedString)
{
    dynamic_string str{20};

    EXPECT_EQ(str.capacity(), 20);
    EXPECT_EQ(str.size(), 0);
    EXPECT_STR(str, "");

    str.append('c');
    EXPECT_EQ(str.capacity(), 20);
    EXPECT_EQ(str.size(), 1);
    EXPECT_STR(str, "c");

    str.append("string");
    EXPECT_EQ(str.capacity(), 20);
    EXPECT_EQ(str.size(), 7);
    EXPECT_STR(str, "cstring");
}

TEST(TestDynamicString, AppendCharsAndStrings)
{
    dynamic_string str;

    EXPECT_EQ(str.capacity(), 0);
    EXPECT_EQ(str.size(), 0);

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
    EXPECT_STR(str, "this is a string that has been appended here");
}

TEST(TestDynamicString, Equality)
{
    dynamic_string hello{"hello"sv};
    dynamic_string bye{"bye"sv};

    EXPECT_NE(hello, bye);
    EXPECT_EQ(hello, hello);
    EXPECT_EQ(bye, bye);

    dynamic_string hello2{"hello"sv};
    EXPECT_NE(hello.data(), hello2.data());
    EXPECT_EQ(hello, hello2);
    EXPECT_EQ(hello2, hello);

    dynamic_string hello_plus{"hello is just a substring"sv};
    EXPECT_NE(hello, hello_plus);
    EXPECT_NE(hello_plus, hello);
}

} // namespace
