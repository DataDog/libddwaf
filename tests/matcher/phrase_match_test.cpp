// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include <algorithm>

using namespace ddwaf::matcher;

TEST(TestPhraseMatch, TestBasic)
{
    std::vector<const char *> strings{"aaaa", "bbbb", "cccc"};
    std::vector<uint32_t> lengths{4, 4, 4};

    phrase_match matcher(strings, lengths);

    EXPECT_STREQ(matcher.name().data(), "phrase_match");
    EXPECT_STREQ(matcher.to_string().data(), "");

    ddwaf_object param;
    ddwaf_object_string(&param, "bbbb");

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STREQ(highlight.c_str(), "bbbb");

    ddwaf_object param2;
    ddwaf_object_string(&param2, "dddd");

    EXPECT_FALSE(matcher.match(param2).first);

    ddwaf_object_free(&param2);
    ddwaf_object_free(&param);
}

TEST(TestPhraseMatch, TestEmptyArrays)
{
    std::vector<const char *> strings;
    std::vector<uint32_t> lengths;
    phrase_match matcher(strings, lengths);

    EXPECT_STREQ(matcher.name().data(), "phrase_match");

    ddwaf_object param;
    ddwaf_object_string(&param, "bbbb");

    EXPECT_FALSE(matcher.match(param).first);

    ddwaf_object_free(&param);
}

TEST(TestPhraseMatch, TestInconsistentArrays)
{
    std::vector<const char *> strings{"aaaa"};
    std::vector<uint32_t> lengths;
    EXPECT_THROW(phrase_match(strings, lengths), std::invalid_argument);
}

TEST(TestPhraseMatch, TestComplex)
{
    std::vector<const char *> strings{"String1", "string2", "string 3", "string_4", "string21"};
    std::vector<uint32_t> lengths(strings.size());
    std::generate(lengths.begin(), lengths.end(),
        [i = 0, &strings]() mutable { return strlen(strings[i++]); });

    phrase_match matcher(strings, lengths);

    auto run = [&matcher](const char *str, const char *expect) {
        ddwaf_object param;
        ddwaf_object_string(&param, str);
        if (expect != nullptr) {
            auto [res, highlight] = matcher.match(param);
            EXPECT_TRUE(res);
            EXPECT_STREQ(highlight.c_str(), expect);
        } else {
            EXPECT_FALSE(matcher.match(param).first);
        }
        ddwaf_object_free(&param);
    };

    run("bla_String1_bla", "String1");
    run("\xF0\x82\x82\xAC\xC1string2\xF0\x82\x82\xAC\xC1", "string2");
    run("bla_string 3", "string 3");
    run("string_4bla", "string_4");
    run("string21", "string2");

    run("", nullptr);
    run("String", nullptr);
    run("string_", nullptr);
    run("String21", nullptr);
    run("nonsense", nullptr);
}

TEST(TestPhraseMatch, TestInvalidInput)
{
    std::vector<const char *> strings{"aaaa", "bbbb", "cccc"};
    std::vector<uint32_t> lengths{4, 4, 4};

    phrase_match matcher(strings, lengths);

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 30}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"*", 0}).first);
}