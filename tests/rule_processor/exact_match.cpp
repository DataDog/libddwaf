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

TEST(TestExactMatch, Expiration)
{
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
                       .count();

    exact_match processor(std::vector<std::pair<std::string_view, uint64_t>>{{"aaaa", now - 1},
        {"bbbb", now + 100}, {"cccc", now - 1}, {"dddd", 0}, {"dddd", now - 1}, {"eeee", now - 1},
        {"eeee", 0}, {"ffff", now + 100}, {"ffff", now}});

    EXPECT_STREQ(processor.name().data(), "exact_match");
    EXPECT_STREQ(processor.to_string().data(), "");

    EXPECT_FALSE(processor.match("aaaa"));
    EXPECT_FALSE(processor.match("cccc"));

    std::string_view input{"bbbb"};
    auto match = processor.match(input);
    EXPECT_TRUE(match);
    EXPECT_STREQ(match->resolved.c_str(), input.data());
    EXPECT_STREQ(match->matched.c_str(), input.data());

    EXPECT_TRUE(processor.match("dddd"));
    EXPECT_TRUE(processor.match("eeee"));
    EXPECT_TRUE(processor.match("ffff"));
}

TEST(TestExactMatch, InvalidMatchInput)
{
    exact_match processor({"aaaa", "bbbb", "cccc"});

    EXPECT_FALSE(processor.match({nullptr, 0}));
    EXPECT_FALSE(processor.match({nullptr, 30}));
    EXPECT_FALSE(processor.match({"aaaa", 0}));
}
