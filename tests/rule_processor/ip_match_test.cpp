// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test.h"
#include <algorithm>

using namespace ddwaf::rule_processor;

bool match(ip_match &processor, std::string_view ip) {
    return processor.match(ip).has_value();
}

TEST(TestIPMatch, Basic)
{
    ip_match processor(std::vector<std::string_view>{
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

    EXPECT_STREQ(processor.to_string().data(), "");
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

TEST(TestIPMatch, CIDR)
{
    ip_match processor(std::vector<std::string_view>{
        "1.2.0.0/16",
        "1234:abdc::0/112",
    });

    EXPECT_FALSE(match(processor, "1.1.0.0"));
    EXPECT_TRUE(match(processor, "1.2.0.0"));
    EXPECT_TRUE(match(processor, "1.2.255.255"));
    EXPECT_FALSE(match(processor, "1.3.0.0"));

    EXPECT_FALSE(match(processor, "1234:abdb::0"));
    EXPECT_TRUE(match(processor, "1234:abdc::0"));
    EXPECT_TRUE(match(processor, "1234:abdc::ffff"));
    EXPECT_FALSE(match(processor, "1234:abdc::1:0"));
}

TEST(TestIPMatch, InvalidInput)
{
    ip_match processor(std::vector<std::string_view>{
        "1.2.3.4",
        "5.6.7.254",
        "::ffff:0102:0304",
        "1234:0:0:0:0:0:0:5678",
    });

    EXPECT_FALSE(processor.match({nullptr, 0}));
    EXPECT_FALSE(processor.match({nullptr, 30}));
    EXPECT_FALSE(processor.match({"*", 0}));
}

TEST(TestIPMatch, Expiration)
{
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    ip_match processor(std::vector<std::pair<std::string_view,uint64_t>>{
        {"1.2.3.4", now - 1},
        {"5.6.7.254", now + 100},
        {"::ffff:0102:0304", now - 1},
        {"1234:0:0:0:0:0:0:5678", now + 100},
        {"::1", now - 1},
        {"abcd::1234:5678:1234:5678", now + 100},
        {"abcd::1234:0:0:0", now - 1},
        {"abcd::1234:ffff:ffff:ffff", now + 100}
    });

    EXPECT_STREQ(processor.to_string().data(), "");
    EXPECT_STREQ(processor.name().data(), "ip_match");

    EXPECT_FALSE(match(processor, "1.2.3.4"));
    EXPECT_TRUE(match(processor, "5.6.7.254"));
    EXPECT_FALSE(match(processor, "::ffff:0102:0304"));
    EXPECT_TRUE(match(processor, "1234:0:0:0:0:0:0:5678"));
    EXPECT_FALSE(match(processor, "::1"));
    EXPECT_TRUE(match(processor, "abcd::1234:5678:1234:5678"));
    EXPECT_FALSE(match(processor, "abcd::1234:0:0:0"));
    EXPECT_TRUE(match(processor, "abcd::1234:ffff:ffff:ffff"));
}
