// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <chrono>

#include "matcher/ip_match.hpp"

#include "common/gtest/utils.hpp"

using namespace ddwaf::matcher;

namespace {

bool match(ip_match &matcher, std::string_view ip) { return matcher.match(ip).first; }

TEST(TestIPMatch, Basic)
{
    ip_match matcher(std::vector<std::string_view>{"1.2.3.4", "5.6.7.254", "::ffff:0102:0304",
        "1234:0:0:0:0:0:0:5678", "::1", "abcd::1234:5678:1234:5678", "abcd::1234:0:0:0",
        "abcd::1234:ffff:ffff:ffff", "42", "bad ip", "other"});

    EXPECT_STREQ(matcher.to_string().data(), "");
    EXPECT_STREQ(matcher.name().data(), "ip_match");

    EXPECT_TRUE(match(matcher, "1.2.3.4"));
    EXPECT_TRUE(match(matcher, "5.6.7.254"));
    EXPECT_TRUE(match(matcher, "::ffff:0102:0304"));
    EXPECT_TRUE(match(matcher, "1234:0:0:0:0:0:0:5678"));
    EXPECT_TRUE(match(matcher, "::1"));
    EXPECT_TRUE(match(matcher, "abcd::1234:5678:1234:5678"));
    EXPECT_TRUE(match(matcher, "abcd::1234:0:0:0"));
    EXPECT_TRUE(match(matcher, "abcd::1234:ffff:ffff:ffff"));

    EXPECT_FALSE(match(matcher, "1.2.3.5"));
    EXPECT_FALSE(match(matcher, "5.6.8.0"));
    EXPECT_FALSE(match(matcher, "::ffff:0102:0305"));
    EXPECT_FALSE(match(matcher, "5.6.8.0"));
    EXPECT_FALSE(match(matcher, "::2"));
    EXPECT_FALSE(match(matcher, "0:1234::5678"));
    EXPECT_FALSE(match(matcher, "abcd:0:1233::"));

    EXPECT_FALSE(match(matcher, ""));
    EXPECT_FALSE(match(matcher, "12345678901234567890123456789012345678901"));
    EXPECT_FALSE(match(matcher, "not an ip"));

    EXPECT_FALSE(match(matcher, "42"));
    EXPECT_FALSE(match(matcher, "bad ip"));
    EXPECT_FALSE(match(matcher, "other"));
}

TEST(TestIPMatch, CIDR)
{
    ip_match matcher(std::vector<std::string_view>{
        "1.2.0.0/16",
        "1234:abdc::0/112",
    });

    EXPECT_FALSE(match(matcher, "1.1.0.0"));
    EXPECT_TRUE(match(matcher, "1.2.0.0"));
    EXPECT_TRUE(match(matcher, "1.2.255.255"));
    EXPECT_FALSE(match(matcher, "1.3.0.0"));

    EXPECT_FALSE(match(matcher, "1234:abdb::0"));
    EXPECT_TRUE(match(matcher, "1234:abdc::0"));
    EXPECT_TRUE(match(matcher, "1234:abdc::ffff"));
    EXPECT_FALSE(match(matcher, "1234:abdc::1:0"));
}

TEST(TestIPMatch, OverlappingCIDR)
{
    ip_match matcher(std::vector<std::string_view>{
        "1.2.0.0/16",
        "1.2.3.4",
        "1234:abdc::0/112",
        "1234:abdc::1",
    });

    EXPECT_FALSE(match(matcher, "1.1.0.0"));
    EXPECT_TRUE(match(matcher, "1.2.0.0"));
    EXPECT_TRUE(match(matcher, "1.2.3.4"));
    EXPECT_TRUE(match(matcher, "1.2.255.255"));
    EXPECT_FALSE(match(matcher, "1.3.0.0"));

    EXPECT_FALSE(match(matcher, "1234:abdb::0"));
    EXPECT_TRUE(match(matcher, "1234:abdc::0"));
    EXPECT_TRUE(match(matcher, "1234:abdc::1"));
    EXPECT_TRUE(match(matcher, "1234:abdc::ffff"));
    EXPECT_FALSE(match(matcher, "1234:abdc::1:0"));
}

TEST(TestIPMatch, InvalidInput)
{
    ip_match matcher(std::vector<std::string_view>{
        "1.2.3.4",
        "5.6.7.254",
        "::ffff:0102:0304",
        "1234:0:0:0:0:0:0:5678",
    });

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"*", 0}).first);
}

TEST(TestIPMatch, Expiration)
{
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
                       .count();

    ip_match matcher(std::vector<std::pair<std::string_view, uint64_t>>{{"1.2.3.4", now - 1},
        {"5.6.7.254", now + 100}, {"::ffff:0102:0304", now - 1},
        {"1234:0:0:0:0:0:0:5678", now + 100}, {"::1", now - 1},
        {"abcd::1234:5678:1234:5678", now + 100}, {"abcd::1234:0:0:0", now - 1},
        {"abcd::1234:ffff:ffff:ffff", now + 100}});

    EXPECT_STREQ(matcher.to_string().data(), "");
    EXPECT_STREQ(matcher.name().data(), "ip_match");

    EXPECT_FALSE(match(matcher, "1.2.3.4"));
    EXPECT_TRUE(match(matcher, "5.6.7.254"));
    EXPECT_FALSE(match(matcher, "::ffff:0102:0304"));
    EXPECT_TRUE(match(matcher, "1234:0:0:0:0:0:0:5678"));
    EXPECT_FALSE(match(matcher, "::1"));
    EXPECT_TRUE(match(matcher, "abcd::1234:5678:1234:5678"));
    EXPECT_FALSE(match(matcher, "abcd::1234:0:0:0"));
    EXPECT_TRUE(match(matcher, "abcd::1234:ffff:ffff:ffff"));
}

TEST(TestIPMatch, OverlappingExpiration)
{
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
                       .count();

    ip_match matcher(std::vector<std::pair<std::string_view, uint64_t>>{{"4.4.4.4", 0},
        {"4.4.4.4", now - 1}, {"5.5.5.5", now - 1}, {"5.5.5.5", 0}, {"1.0.0.0/8", now - 1},
        {"1.2.3.4", now + 100}, {"2.2.0.0/16", now + 100}, {"2.2.7.8", now - 100},
        {"2.3.0.0/16", 0}, {"2.3.9.1", now - 100}, {"2.4.0.0/16", now - 1}, {"2.4.3.4", 0}});

    EXPECT_STREQ(matcher.to_string().data(), "");
    EXPECT_STREQ(matcher.name().data(), "ip_match");

    EXPECT_TRUE(match(matcher, "4.4.4.4"));
    EXPECT_TRUE(match(matcher, "5.5.5.5"));

    EXPECT_FALSE(match(matcher, "1.1.1.1"));
    EXPECT_TRUE(match(matcher, "1.2.3.4"));

    EXPECT_TRUE(match(matcher, "2.2.0.1"));
    EXPECT_TRUE(match(matcher, "2.2.7.8"));

    EXPECT_TRUE(match(matcher, "2.3.0.1"));
    EXPECT_TRUE(match(matcher, "2.3.9.1"));

    EXPECT_FALSE(match(matcher, "2.4.0.1"));
    EXPECT_TRUE(match(matcher, "2.4.3.4"));
}

} // namespace
