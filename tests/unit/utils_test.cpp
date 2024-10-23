// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <unordered_map>

#include "utils.hpp"

#include "common/gtest/utils.hpp"

using namespace ddwaf;

namespace {
constexpr char char_min = std::numeric_limits<char>::min();
constexpr char char_max = std::numeric_limits<char>::max();

TEST(TestUtils, IsAlpha)
{
    for (char c = char_min; c < char_max; ++c) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            EXPECT_TRUE(isalpha(c));
        } else {
            EXPECT_FALSE(isalpha(c));
        }
    }
}

TEST(TestUtils, IsDigit)
{
    for (char c = char_min; c < char_max; ++c) {
        if (c >= '0' && c <= '9') {
            EXPECT_TRUE(isdigit(c));
        } else {
            EXPECT_FALSE(isdigit(c));
        }
    }
}

TEST(TestUtils, IsXDigit)
{
    for (char c = char_min; c < char_max; ++c) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
            EXPECT_TRUE(isxdigit(c));
        } else {
            EXPECT_FALSE(isxdigit(c));
        }
    }
}

TEST(TestUtils, IsSpace)
{
    for (char c = char_min; c < char_max; ++c) {
        if (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v') {
            EXPECT_TRUE(isspace(c));
        } else {
            EXPECT_FALSE(isspace(c));
        }
    }
}

TEST(TestUtils, IsUpper)
{
    for (char c = char_min; c < char_max; ++c) {
        if (c >= 'A' && c <= 'Z') {
            EXPECT_TRUE(isupper(c));
        } else {
            EXPECT_FALSE(isupper(c));
        }
    }
}

TEST(TestUtils, IsLower)
{
    for (char c = char_min; c < char_max; ++c) {
        if (c >= 'a' && c <= 'z') {
            EXPECT_TRUE(islower(c));
        } else {
            EXPECT_FALSE(islower(c));
        }
    }
}

TEST(TestUtils, IsAlnum)
{
    for (char c = char_min; c < char_max; ++c) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            EXPECT_TRUE(isalnum(c));
        } else {
            EXPECT_FALSE(isalnum(c));
        }
    }
}

TEST(TestUtils, IsBoundary)
{
    for (char c = char_min; c < char_max; ++c) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            c == '_') {
            EXPECT_FALSE(isboundary(c));
        } else {
            EXPECT_TRUE(isboundary(c));
        }
    }
}
TEST(TestUtils, ToLower)
{
    std::unordered_map<char, char> mapping{{'A', 'a'}, {'B', 'b'}, {'C', 'c'}, {'D', 'd'},
        {'E', 'e'}, {'F', 'f'}, {'G', 'g'}, {'H', 'h'}, {'I', 'i'}, {'J', 'j'}, {'K', 'k'},
        {'L', 'l'}, {'M', 'm'}, {'N', 'n'}, {'O', 'o'}, {'P', 'p'}, {'Q', 'q'}, {'R', 'r'},
        {'S', 's'}, {'T', 't'}, {'U', 'u'}, {'V', 'v'}, {'W', 'w'}, {'X', 'x'}, {'Y', 'y'},
        {'Z', 'z'}};

    for (char c = char_min; c < char_max; ++c) {
        auto lc = tolower(c);
        EXPECT_FALSE((lc >= 'A' && lc <= 'Z'));

        if (c >= 'A' && c <= 'Z') {
            EXPECT_EQ(mapping[c], lc);
        }
    }
}

TEST(TestUtils, ToUpper)
{
    std::unordered_map<char, char> mapping{{'a', 'A'}, {'b', 'B'}, {'c', 'C'}, {'d', 'D'},
        {'e', 'E'}, {'f', 'F'}, {'g', 'G'}, {'h', 'H'}, {'i', 'I'}, {'j', 'J'}, {'k', 'K'},
        {'l', 'L'}, {'m', 'M'}, {'n', 'N'}, {'o', 'O'}, {'p', 'P'}, {'q', 'Q'}, {'r', 'R'},
        {'s', 'S'}, {'t', 'T'}, {'u', 'U'}, {'v', 'V'}, {'w', 'W'}, {'x', 'X'}, {'y', 'Y'},
        {'z', 'Z'}};

    for (char c = char_min; c < char_max; ++c) {
        auto lc = toupper(c);
        EXPECT_FALSE((lc >= 'a' && lc <= 'z'));

        if (c >= 'a' && c <= 'z') {
            EXPECT_EQ(mapping[c], lc);
        }
    }
}

TEST(TestUtils, FromHex)
{
    std::unordered_map<char, uint8_t> mapping{{'0', 0}, {'1', 1}, {'2', 2}, {'3', 3}, {'4', 4},
        {'5', 5}, {'6', 6}, {'7', 7}, {'8', 8}, {'9', 9}, {'a', 0xa}, {'b', 0xb}, {'c', 0xc},
        {'d', 0xd}, {'e', 0xe}, {'f', 0xf}};

    for (auto [c, expected] : mapping) {
        auto obtained = from_hex(c);
        EXPECT_EQ(expected, obtained);
    }
}

TEST(TestUtils, CloneInvalid)
{
    ddwaf_object input;
    ddwaf_object_invalid(&input);

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_INVALID);
}

TEST(TestUtils, CloneNull)
{
    ddwaf_object input;
    ddwaf_object_null(&input);

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_NULL);
}

TEST(TestUtils, CloneBool)
{
    ddwaf_object input;
    ddwaf_object_bool(&input, true);

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_BOOL);
    EXPECT_EQ(output.boolean, true);
}

TEST(TestUtils, CloneSigned)
{
    ddwaf_object input;
    ddwaf_object_signed(&input, -5);

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_SIGNED);
    EXPECT_EQ(output.intValue, -5);
}

TEST(TestUtils, CloneUnsigned)
{
    ddwaf_object input;
    ddwaf_object_unsigned(&input, 5);

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(output.uintValue, 5);
}

TEST(TestUtils, CloneFloat)
{
    ddwaf_object input;
    ddwaf_object_float(&input, 5.1);

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_FLOAT);
    EXPECT_TRUE(std::abs(output.f64 - 5.1) < 0.1);
}

TEST(TestUtils, CloneString)
{
    ddwaf_object input;
    ddwaf_object_string(&input, "this is a string");

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_STRING);
    EXPECT_STREQ(input.stringValue, output.stringValue);
    EXPECT_EQ(input.nbEntries, output.nbEntries);
    EXPECT_NE(input.stringValue, output.stringValue);

    ddwaf_object_free(&input);
    ddwaf_object_free(&output);
}

TEST(TestUtils, CloneEmptyArray)
{
    ddwaf_object input;
    ddwaf_object_array(&input);

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(input.nbEntries, output.nbEntries);

    ddwaf_object_free(&input);
    ddwaf_object_free(&output);
}

TEST(TestUtils, CloneEmptyMap)
{
    ddwaf_object input;
    ddwaf_object_map(&input);

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(input.nbEntries, output.nbEntries);

    ddwaf_object_free(&input);
    ddwaf_object_free(&output);
}

TEST(TestUtils, CloneArray)
{
    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_array(&input);
    ddwaf_object_array_add(&input, ddwaf_object_bool(&tmp, true));
    ddwaf_object_array_add(&input, ddwaf_object_string(&tmp, "string"));
    ddwaf_object_array_add(&input, ddwaf_object_signed(&tmp, 5));

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_ARRAY);
    EXPECT_EQ(input.nbEntries, output.nbEntries);

    {
        const auto *input_child = ddwaf_object_get_index(&input, 0);
        const auto *output_child = ddwaf_object_get_index(&output, 0);

        EXPECT_NE(output_child, input_child);
        EXPECT_EQ(output_child->type, input_child->type);
        EXPECT_EQ(output_child->boolean, input_child->boolean);
    }

    {
        const auto *input_child = ddwaf_object_get_index(&input, 1);
        const auto *output_child = ddwaf_object_get_index(&output, 1);

        EXPECT_NE(output_child, input_child);
        EXPECT_EQ(output_child->type, input_child->type);
        EXPECT_STREQ(output_child->stringValue, input_child->stringValue);
        EXPECT_NE(output_child->stringValue, input_child->stringValue);
    }

    {
        const auto *input_child = ddwaf_object_get_index(&input, 2);
        const auto *output_child = ddwaf_object_get_index(&output, 2);

        EXPECT_NE(output_child, input_child);
        EXPECT_EQ(output_child->type, input_child->type);
        EXPECT_EQ(output_child->intValue, input_child->intValue);
    }

    ddwaf_object_free(&input);
    ddwaf_object_free(&output);
}

TEST(TestUtils, CloneMap)
{
    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_map(&input);
    ddwaf_object_map_add(&input, "bool", ddwaf_object_bool(&tmp, true));
    ddwaf_object_map_add(&input, "string", ddwaf_object_string(&tmp, "string"));
    ddwaf_object_map_add(&input, "signed", ddwaf_object_signed(&tmp, 5));

    auto output = object::clone(&input);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(input.nbEntries, output.nbEntries);

    {
        const auto *input_child = ddwaf_object_get_index(&input, 0);
        const auto *output_child = ddwaf_object_get_index(&output, 0);

        EXPECT_NE(output_child, input_child);
        EXPECT_STREQ(output_child->parameterName, input_child->parameterName);
        EXPECT_NE(output_child->parameterName, input_child->parameterName);
        EXPECT_EQ(output_child->parameterNameLength, input_child->parameterNameLength);
        EXPECT_EQ(output_child->type, input_child->type);
        EXPECT_EQ(output_child->boolean, input_child->boolean);
    }

    {
        const auto *input_child = ddwaf_object_get_index(&input, 1);
        const auto *output_child = ddwaf_object_get_index(&output, 1);

        EXPECT_NE(output_child, input_child);
        EXPECT_STREQ(output_child->parameterName, input_child->parameterName);
        EXPECT_NE(output_child->parameterName, input_child->parameterName);
        EXPECT_EQ(output_child->parameterNameLength, input_child->parameterNameLength);
        EXPECT_EQ(output_child->type, input_child->type);
        EXPECT_STREQ(output_child->stringValue, input_child->stringValue);
        EXPECT_NE(output_child->stringValue, input_child->stringValue);
    }

    {
        const auto *input_child = ddwaf_object_get_index(&input, 2);
        const auto *output_child = ddwaf_object_get_index(&output, 2);

        EXPECT_NE(output_child, input_child);
        EXPECT_STREQ(output_child->parameterName, input_child->parameterName);
        EXPECT_NE(output_child->parameterName, input_child->parameterName);
        EXPECT_EQ(output_child->parameterNameLength, input_child->parameterNameLength);
        EXPECT_EQ(output_child->type, input_child->type);
        EXPECT_EQ(output_child->intValue, input_child->intValue);
    }

    ddwaf_object_free(&input);
    ddwaf_object_free(&output);
}

#define EXPECT_VEC(expected, ...)                                                                  \
    {                                                                                              \
        std::vector<std::string_view> vec{__VA_ARGS__};                                            \
        EXPECT_EQ(expected, vec);                                                                  \
    }

TEST(TestUtils, Split)
{
    EXPECT_VEC(ddwaf::split("|", '|'));
    EXPECT_VEC(ddwaf::split("||", '|'));
    EXPECT_VEC(ddwaf::split("|||||||", '|'));
    EXPECT_VEC(ddwaf::split("value", '|'), "value");
    EXPECT_VEC(ddwaf::split("|value", '|'), "value");
    EXPECT_VEC(ddwaf::split("value|", '|'), "value");
    EXPECT_VEC(ddwaf::split("|value|", '|'), "value");
    EXPECT_VEC(ddwaf::split("||||value||||", '|'), "value");
    EXPECT_VEC(ddwaf::split("hello|value", '|'), "hello", "value");
    EXPECT_VEC(ddwaf::split("hello|value|", '|'), "hello", "value");
    EXPECT_VEC(ddwaf::split("|hello|value", '|'), "hello", "value");
    EXPECT_VEC(ddwaf::split("|hello|value|", '|'), "hello", "value");
    EXPECT_VEC(ddwaf::split("a,b,c,d,e,f,g", ','), "a", "b", "c", "d", "e", "f", "g");
}

} // namespace
