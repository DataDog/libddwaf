// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "test.hpp"
#include "utils.hpp"

using namespace ddwaf;

namespace {
constexpr char char_min = std::numeric_limits<char>::min();
constexpr char char_max = std::numeric_limits<char>::max();

TEST(TestUtils, TestIsAlpha)
{
    for (char c = char_min; c < char_max; ++c) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            EXPECT_TRUE(isalpha(c));
        } else {
            EXPECT_FALSE(isalpha(c));
        }
    }
}

TEST(TestUtils, TestIsDigit)
{
    for (char c = char_min; c < char_max; ++c) {
        if (c >= '0' && c <= '9') {
            EXPECT_TRUE(isdigit(c));
        } else {
            EXPECT_FALSE(isdigit(c));
        }
    }
}

TEST(TestUtils, TestIsXDigit)
{
    for (char c = char_min; c < char_max; ++c) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
            EXPECT_TRUE(isxdigit(c));
        } else {
            EXPECT_FALSE(isxdigit(c));
        }
    }
}

TEST(TestUtils, TestIsSpace)
{
    for (char c = char_min; c < char_max; ++c) {
        if (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v') {
            EXPECT_TRUE(isspace(c));
        } else {
            EXPECT_FALSE(isspace(c));
        }
    }
}

TEST(TestUtils, TestIsUpper)
{
    for (char c = char_min; c < char_max; ++c) {
        if (c >= 'A' && c <= 'Z') {
            EXPECT_TRUE(isupper(c));
        } else {
            EXPECT_FALSE(isupper(c));
        }
    }
}

TEST(TestUtils, TestIsLower)
{
    for (char c = char_min; c < char_max; ++c) {
        if (c >= 'a' && c <= 'z') {
            EXPECT_TRUE(islower(c));
        } else {
            EXPECT_FALSE(islower(c));
        }
    }
}

TEST(TestUtils, TestIsAlnum)
{
    for (char c = char_min; c < char_max; ++c) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            EXPECT_TRUE(isalnum(c));
        } else {
            EXPECT_FALSE(isalnum(c));
        }
    }
}

TEST(TestUtils, TestToLower)
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

TEST(TestUtils, TestToUpper)
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

TEST(TestUtils, TestFromHex)
{
    std::unordered_map<char, uint8_t> mapping{{'0', 0}, {'1', 1}, {'2', 2}, {'3', 3}, {'4', 4},
        {'5', 5}, {'6', 6}, {'7', 7}, {'8', 8}, {'9', 9}, {'a', 0xa}, {'b', 0xb}, {'c', 0xc},
        {'d', 0xd}, {'e', 0xe}, {'f', 0xf}};

    for (auto [c, expected] : mapping) {
        auto obtained = from_hex(c);
        EXPECT_EQ(expected, obtained);
    }
}

} // namespace
