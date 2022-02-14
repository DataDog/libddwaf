// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include <algorithm>

TEST(TestPhraseMatch, TestBasic)
{
    std::vector<const char*> strings { "aaaa", "bbbb", "cccc" };
    std::vector<uint32_t> lengths { 4, 4, 4 };

    PerfMatch processor(strings, lengths);

    EXPECT_STREQ(processor.operatorName().data(), "phrase_match");

    MatchGatherer gatherer;
    ddwaf_object param;
    ddwaf_object_string(&param, "bbbb");

    EXPECT_TRUE(processor.doesMatch(&param, gatherer));

    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "bbbb");
    EXPECT_STREQ(gatherer.matchedValue.c_str(), "bbbb");

    ddwaf_object param2;
    ddwaf_object_string(&param2, "dddd");

    EXPECT_FALSE(processor.doesMatch(&param2, gatherer));

    ddwaf_object_free(&param2);
    ddwaf_object_free(&param);
}

TEST(TestPhraseMatch, TestEmptyArrays)
{
    std::vector<const char*> strings;
    std::vector<uint32_t> lengths;
    PerfMatch processor(strings, lengths);

    EXPECT_STREQ(processor.operatorName().data(), "phrase_match");

    MatchGatherer gatherer;
    ddwaf_object param;
    ddwaf_object_string(&param, "bbbb");

    EXPECT_FALSE(processor.doesMatch(&param, gatherer));

    ddwaf_object_free(&param);
}

TEST(TestPhraseMatch, TestInconsistentArrays)
{
    std::vector<const char*> strings { "aaaa" };
    std::vector<uint32_t> lengths;
    EXPECT_THROW(PerfMatch(strings, lengths), std::invalid_argument);
}

TEST(TestPhraseMatch, TestComplex)
{
    std::vector<const char*> strings { "String1", "string2", "string 3", "string_4", "string21" };
    std::vector<uint32_t> lengths(strings.size());
    std::generate(lengths.begin(), lengths.end(),
                  [i = 0, &strings]() mutable { return strlen(strings[i++]); });

    PerfMatch processor(strings, lengths);

    auto run = [&processor](const char* str, const char* expect) {
        MatchGatherer gatherer;
        ddwaf_object param;
        ddwaf_object_string(&param, str);
        if (expect)
        {
            EXPECT_TRUE(processor.doesMatch(&param, gatherer));
            EXPECT_STREQ(gatherer.resolvedValue.c_str(), str);
            EXPECT_STREQ(gatherer.matchedValue.c_str(), expect);
        }
        else
        {
            EXPECT_FALSE(processor.doesMatch(&param, gatherer));
        }
        ddwaf_object_free(&param);
    };

    run("bla_String1_bla", "String1");
    run("\xF0\x82\x82\xAC\xC1string2\xF0\x82\x82\xAC\xC1", "string2");
    run("bla_string 3", "string 3");
    run("string_4bla", "string_4");
    run("string21", "string2");

    run("", NULL);
    run("String", NULL);
    run("string_", NULL);
    run("String21", NULL);
    run("nonsense", NULL);
}
