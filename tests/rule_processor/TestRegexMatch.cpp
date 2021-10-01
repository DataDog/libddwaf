// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"

TEST(TestRegexMatch, TestBasicCaseInsensitive)
{
    RE2Manager processor("^rEgEx$", false);
    EXPECT_STREQ(processor.getStringRepresentation().c_str(), "^rEgEx$");
    EXPECT_STREQ(processor.operatorName().data(), "match_regex");

    std::vector<uint8_t> matchestogather;
    MatchGatherer gatherer(matchestogather);
    ddwaf_object param;
    ddwaf_object_string(&param, "regex");

    EXPECT_TRUE(processor.doesMatch(&param, gatherer));

    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "regex");
    EXPECT_STREQ(gatherer.matchedValue.c_str(), "regex");

    ddwaf_object_free(&param);
}

TEST(TestRegexMatch, TestBasicCaseSensitive)
{
    RE2Manager processor("^rEgEx$", true);
    EXPECT_STREQ(processor.getStringRepresentation().c_str(), "^rEgEx$");
    EXPECT_STREQ(processor.operatorName().data(), "match_regex");

    std::vector<uint8_t> matchestogather;
    MatchGatherer gatherer(matchestogather);
    ddwaf_object param;
    ddwaf_object_string(&param, "regex");

    EXPECT_FALSE(processor.doesMatch(&param, gatherer));

    ddwaf_object param2;
    ddwaf_object_string(&param2, "rEgEx");

    EXPECT_TRUE(processor.doesMatch(&param2, gatherer));
    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "rEgEx");
    EXPECT_STREQ(gatherer.matchedValue.c_str(), "rEgEx");

    ddwaf_object_free(&param);
    ddwaf_object_free(&param2);
}

TEST(TestRegexMatch, TestCaptureGroups)
{
    RE2Manager processor("^(regex)(.*)$", false);
    EXPECT_STREQ(processor.getStringRepresentation().c_str(), "^(regex)(.*)$");
    EXPECT_STREQ(processor.operatorName().data(), "match_regex");

    std::vector<uint8_t> matchestogather { 1, 2 };
    MatchGatherer gatherer(matchestogather);
    ddwaf_object param;
    ddwaf_object_string(&param, "regexsomething");

    EXPECT_TRUE(processor.doesMatch(&param, gatherer));

    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "regexsomething");
    EXPECT_STREQ(gatherer.matchedValue.c_str(), "regexsomething");
    EXPECT_EQ(gatherer.submatches.size(), 2);

    EXPECT_EQ(gatherer.submatches[0].first, 1);
    EXPECT_STREQ(gatherer.submatches[0].second.c_str(), "regex");
    EXPECT_EQ(gatherer.submatches[1].first, 2);
    EXPECT_STREQ(gatherer.submatches[1].second.c_str(), "something");

    ddwaf_object_free(&param);
}

TEST(TestRegexMatch, TestBadRegex)
{
    EXPECT_THROW(RE2Manager("(?:<\\?(?!xml\\s)|<\\?php|\\[(?:/|\\\\\\\\)?php\\])", true),
                 parsing_error);
}

TEST(TestRegexMatch, TestComplexRegex)
{
    RE2Manager processor("^(?i:(?:[a-z]{3,10}\\s+(?:\\w{3,7}?://[\\w\\-\\./]*(?::\\d+)?)?/[^?#]*(?:\\?[^#\\s]*)?(?:#[\\S]*)?|connect (?:\\d{1,3}\\.){3}\\d{1,3}\\.?(?::\\d+)?|options \\*)\\s+[\\w\\./]+|get /[^?#]*(?:\\?[^#\\s]*)?(?:#[\\S]*)?)$", false);

    ddwaf_object param;
    ddwaf_object_string(&param, "GET /test.php:blablabla");
    std::vector<uint8_t> submatch;
    MatchGatherer gather(submatch);

    //First regex should create the DFA (or run out of memory)
    EXPECT_TRUE(processor.doesMatch(&param, gather));
    ddwaf_object_free(&param);
}
