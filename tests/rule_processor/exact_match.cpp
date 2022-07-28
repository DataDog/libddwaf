// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include <algorithm>

using namespace ddwaf::rule_processor;

TEST(TestExactMatch, Basic)
{
    exact_match processor({"aaaa", "bbbb", "cccc"});

    EXPECT_STREQ(processor.name().data(), "exact_match");
    EXPECT_STREQ(processor.to_string().c_str(), "");

    MatchGatherer gatherer;
    {
        std::string_view match{"aaaa"};
        EXPECT_TRUE(processor.match(match.data(), match.size(), gatherer));
        EXPECT_STREQ(gatherer.resolvedValue.c_str(), match.data());
        EXPECT_STREQ(gatherer.matchedValue.c_str(), match.data());
    }

    {
        std::string_view match{"bbbb"};
        EXPECT_TRUE(processor.match(match.data(), match.size(), gatherer));
        EXPECT_STREQ(gatherer.resolvedValue.c_str(), match.data());
        EXPECT_STREQ(gatherer.matchedValue.c_str(), match.data());
    }

    {
        std::string_view match{"cccc"};
        EXPECT_TRUE(processor.match(match.data(), match.size(), gatherer));
        EXPECT_STREQ(gatherer.resolvedValue.c_str(), match.data());
        EXPECT_STREQ(gatherer.matchedValue.c_str(), match.data());
    }

    {
        std::string_view match{"cc"};
        EXPECT_FALSE(processor.match(match.data(), match.size(), gatherer));
    }

    {
        std::string_view match{"aaaaaa"};
        EXPECT_FALSE(processor.match(match.data(), match.size(), gatherer));
    }

    {
        std::string_view match{"ddddd"};
        EXPECT_FALSE(processor.match(match.data(), match.size(), gatherer));
    }
}
