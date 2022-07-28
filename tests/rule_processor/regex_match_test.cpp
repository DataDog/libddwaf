// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"

using namespace ddwaf::rule_processor;

TEST(TestRegexMatch, TestBasicCaseInsensitive)
{
    regex_match processor("^rEgEx$", 0, false);
    EXPECT_STREQ(processor.to_string().c_str(), "^rEgEx$");
    EXPECT_STREQ(processor.name().data(), "match_regex");

    MatchGatherer gatherer;
    ddwaf_object param;
    ddwaf_object_string(&param, "regex");

    EXPECT_TRUE(processor.match_object(&param, gatherer));

    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "regex");
    EXPECT_STREQ(gatherer.matchedValue.c_str(), "regex");

    ddwaf_object_free(&param);
}

TEST(TestRegexMatch, TestBasicCaseSensitive)
{
    regex_match processor("^rEgEx$", 0, true);
    EXPECT_STREQ(processor.to_string().c_str(), "^rEgEx$");
    EXPECT_STREQ(processor.name().data(), "match_regex");

    MatchGatherer gatherer;
    ddwaf_object param;
    ddwaf_object_string(&param, "regex");

    EXPECT_FALSE(processor.match_object(&param, gatherer));

    ddwaf_object param2;
    ddwaf_object_string(&param2, "rEgEx");

    EXPECT_TRUE(processor.match_object(&param2, gatherer));
    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "rEgEx");
    EXPECT_STREQ(gatherer.matchedValue.c_str(), "rEgEx");

    ddwaf_object_free(&param);
    ddwaf_object_free(&param2);
}

TEST(TestRegexMatch, TestMinLength)
{
    regex_match processor("^rEgEx.*$", 6, true);
    EXPECT_STREQ(processor.to_string().c_str(), "^rEgEx.*$");
    EXPECT_STREQ(processor.name().data(), "match_regex");

    MatchGatherer gatherer;
    ddwaf_object param, param2;
    ddwaf_object_string(&param, "rEgEx");
    ddwaf_object_string(&param2, "rEgExe");

    EXPECT_FALSE(processor.match_object(&param, gatherer));
    EXPECT_TRUE(processor.match_object(&param2, gatherer));
    EXPECT_STREQ(gatherer.resolvedValue.c_str(), "rEgExe");
    EXPECT_STREQ(gatherer.matchedValue.c_str(), "rEgExe");

    ddwaf_object_free(&param);
    ddwaf_object_free(&param2);
}
