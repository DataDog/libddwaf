// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include <algorithm>

using namespace ddwaf::rule_processor;

bool match(ip_match &processor, std::string_view ip) {
    MatchGatherer mg;
    return processor.match(ip.data(), ip.size(), mg);
}

TEST(TestIPMatch, Basic)
{
    ip_match processor({
        "1.2.3.4",
        "5.6.7.254",
        "::ffff:0102:0304",
        "1234:0:0:0:0:0:0:5678",
        "::1",
        "abcd::1234:5678:1234:5678",
        "abcd::1234:0:0:0",
        "abcd::1234:ffff:ffff:ffff",
        "42",
        "bad ip",
        "other"
    });

    EXPECT_STREQ(processor.to_string().c_str(), "");
    EXPECT_STREQ(processor.name().data(), "ip_match");

    EXPECT_TRUE(match(processor, "1.2.3.4"));
    EXPECT_TRUE(match(processor, "5.6.7.254"));
    EXPECT_TRUE(match(processor, "::ffff:0102:0304"));
    EXPECT_TRUE(match(processor, "1234:0:0:0:0:0:0:5678"));
    EXPECT_TRUE(match(processor, "::1"));
    EXPECT_TRUE(match(processor, "abcd::1234:5678:1234:5678"));
    EXPECT_TRUE(match(processor, "abcd::1234:0:0:0"));
    EXPECT_TRUE(match(processor, "abcd::1234:ffff:ffff:ffff"));

    EXPECT_FALSE(match(processor, "1.2.3.5"));
    EXPECT_FALSE(match(processor, "5.6.8.0"));
    EXPECT_FALSE(match(processor, "::ffff:0102:0305"));
    EXPECT_FALSE(match(processor, "5.6.8.0"));
    EXPECT_FALSE(match(processor, "::2"));
    EXPECT_FALSE(match(processor, "0:1234::5678"));
    EXPECT_FALSE(match(processor, "abcd:0:1233::"));

    EXPECT_FALSE(match(processor, ""));
    EXPECT_FALSE(match(processor, "12345678901234567890123456789012345678901"));
    EXPECT_FALSE(match(processor, "not an ip"));

    EXPECT_FALSE(match(processor, "42"));
    EXPECT_FALSE(match(processor, "bad ip"));
    EXPECT_FALSE(match(processor, "other"));
}

TEST(TestIPMatch, TestCIDR)
{
    ip_match processor({
        "1.2.0.0/16",
        "1234:abdc::0/112",
    });

    MatchGatherer gatherer;

    EXPECT_FALSE(match(processor, "1.1.0.0"));
    EXPECT_TRUE(match(processor, "1.2.0.0"));
    EXPECT_TRUE(match(processor, "1.2.255.255"));
    EXPECT_FALSE(match(processor, "1.3.0.0"));

    EXPECT_FALSE(match(processor, "1234:abdb::0"));
    EXPECT_TRUE(match(processor, "1234:abdc::0"));
    EXPECT_TRUE(match(processor, "1234:abdc::ffff"));
    EXPECT_FALSE(match(processor, "1234:abdc::1:0"));
}

TEST(TestIPMatch, TestInvalidInput)
{
    ip_match processor({
        "1.2.3.4",
        "5.6.7.254",
        "::ffff:0102:0304",
        "1234:0:0:0:0:0:0:5678",
    });

    MatchGatherer gatherer;
    EXPECT_FALSE(processor.match(nullptr, 0,  gatherer));
    EXPECT_FALSE(processor.match(nullptr, 30,  gatherer));
    EXPECT_FALSE(processor.match("*", 0,  gatherer));
}
