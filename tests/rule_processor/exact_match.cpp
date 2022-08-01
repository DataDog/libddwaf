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
    EXPECT_STREQ(processor.to_string().data(), "");

    {
        std::string_view input{"aaaa"};
        auto match = processor.match(input);
        EXPECT_TRUE(match);
        EXPECT_STREQ(match->resolved.c_str(), input.data());
        EXPECT_STREQ(match->matched.c_str(), input.data());
    }

    {
        std::string_view input{"bbbb"};
        auto match = processor.match(input);
        EXPECT_TRUE(match);
        EXPECT_STREQ(match->resolved.c_str(), input.data());
        EXPECT_STREQ(match->matched.c_str(), input.data());
    }

    {
        std::string_view input{"cccc"};
        auto match = processor.match(input);
        EXPECT_TRUE(match);
        EXPECT_STREQ(match->resolved.c_str(), input.data());
        EXPECT_STREQ(match->matched.c_str(), input.data());
    }

    {
        std::string_view input{"cc"};
        auto match = processor.match(input);
        EXPECT_FALSE(match);
    }

    {
        std::string_view input{"aaaaaa"};
        auto match = processor.match(input);
        EXPECT_FALSE(match);
    }

    {
        std::string_view input{"ddddd"};
        auto match = processor.match(input);
        EXPECT_FALSE(match);
    }
}

TEST(TestExactMatch, InvalidMatchInput)
{
    exact_match processor({"aaaa", "bbbb", "cccc"});

    EXPECT_FALSE(processor.match({nullptr, 0}));
    EXPECT_FALSE(processor.match({nullptr, 30}));
    EXPECT_FALSE(processor.match({"aaaa", 0}));
}
