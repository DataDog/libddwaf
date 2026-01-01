// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/phrase_match.hpp"

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace ddwaf::matcher;

namespace {

TEST(TestPhraseMatch, TestBasic)
{
    std::vector<const char *> strings{"aaaa", "bbbb", "cccc"};
    std::vector<uint32_t> lengths{4, 4, 4};

    phrase_match matcher(strings, lengths);

    EXPECT_STRV(matcher.name(), "phrase_match");
    EXPECT_STRV(matcher.to_string(), "");

    owned_object param = test::ddwaf_object_da::make_string("bbbb");

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "bbbb");

    owned_object param2 = test::ddwaf_object_da::make_string("dddd");

    EXPECT_FALSE(matcher.match(param2).first);
}

TEST(TestPhraseMatch, TestEmptyArrays)
{
    std::vector<const char *> strings;
    std::vector<uint32_t> lengths;
    phrase_match matcher(strings, lengths);

    EXPECT_STRV(matcher.name(), "phrase_match");

    owned_object param = test::ddwaf_object_da::make_string("bbbb");

    EXPECT_FALSE(matcher.match(param).first);
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
        owned_object param = test::ddwaf_object_da::make_string(str);
        if (expect != nullptr) {
            auto [res, highlight] = matcher.match(ddwaf::object_view{param});
            EXPECT_TRUE(res);
            EXPECT_STR(highlight, expect);
        } else {
            EXPECT_FALSE(matcher.match(ddwaf::object_view{param}).first);
        }
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

TEST(TestPhraseMatch, TestWordBoundary)
{
    std::vector<const char *> strings{"banana", "$apple", "orange$", "$pear$"};
    std::vector<uint32_t> lengths(strings.size());
    std::generate(lengths.begin(), lengths.end(),
        [i = 0, &strings]() mutable { return strlen(strings[i++]); });

    phrase_match matcher(strings, lengths, true);

    auto run = [&matcher](const char *str, const char *expect) {
        owned_object param = test::ddwaf_object_da::make_string(str);
        if (expect != nullptr) {
            auto [res, highlight] = matcher.match(ddwaf::object_view{param});
            EXPECT_TRUE(res);
            EXPECT_STR(highlight, expect);
        } else {
            EXPECT_FALSE(matcher.match(ddwaf::object_view{param}).first);
        }
    };

    run("banana", "banana");
    run(" banana", "banana");
    run("banana ", "banana");
    run("word banana word", "banana");
    run("word   ;banana/ word", "banana");

    run("banan", nullptr);
    run("abanana", nullptr);
    run("bananaa", nullptr);
    run("abananaa", nullptr);
    run("banana_", nullptr);
    run("_banana", nullptr);
    run("_banana_", nullptr);
    run("   _banana   ", nullptr);
    run("   banana_   ", nullptr);
    run("   _banana_   ", nullptr);

    run("$apple", "$apple");
    run("s$apple", "$apple");
    run(";$apple", "$apple");
    run(";$apple;", "$apple");
    run("$apple;", "$apple");
    run("word $apple word", "$apple");

    run("apple", nullptr);
    run("$applea", nullptr);
    run("a$applea", nullptr);
    run("$apple_", nullptr);
    run("_$apple_", nullptr);
    run("   $apple_   ", nullptr);
    run("   _$apple_   ", nullptr);

    run("orange$", "orange$");
    run("orange$s", "orange$");
    run(";orange$", "orange$");
    run(";orange$;", "orange$");
    run("orange$;", "orange$");
    run("word orange$word", "orange$");

    run("orange", nullptr);
    run("aorange$", nullptr);
    run("aorange$a", nullptr);
    run("_orange$", nullptr);
    run("_orange$_", nullptr);
    run("   _orange$   ", nullptr);
    run("   _orange$_   ", nullptr);

    run("$pear$", "$pear$");
    run("$pear$s", "$pear$");
    run("s$pear$", "$pear$");
    run("s$pear$s", "$pear$");
    run(";$pear$", "$pear$");
    run(";$pear$;", "$pear$");
    run("$pear$;", "$pear$");
    run("word$pear$word", "$pear$");
    run("word $pear$ word", "$pear$");

    run("pear$", nullptr);
    run("$pear", nullptr);
}

TEST(TestPhraseMatch, TestInvalidInput)
{
    std::vector<const char *> strings{"aaaa", "bbbb", "cccc"};
    std::vector<uint32_t> lengths{4, 4, 4};

    phrase_match matcher(strings, lengths);

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"*", 0}).first);
}

TEST(TestPhraseMatch, TestSingleCharMatch)
{
    std::vector<const char *> strings{"a", "1"};
    std::vector<uint32_t> lengths{1, 1};

    phrase_match matcher(strings, lengths);

    EXPECT_STR(matcher.name(), "phrase_match");
    EXPECT_STR(matcher.to_string(), "");

    owned_object param = test::ddwaf_object_da::make_string("a");

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "a");

    owned_object param2 = test::ddwaf_object_da::make_string("2");

    EXPECT_FALSE(matcher.match(param2).first);
}

} // namespace
