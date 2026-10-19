// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

#include "ip_utils.hpp"

#include "common/gtest_utils.hpp"

namespace {

TEST(TestIP, ParsingIPv4)
{
    {
        ddwaf::ipaddr ip{};
        EXPECT_TRUE(ddwaf::parse_ip("1.2.3.4", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4);
        EXPECT_EQ(ip.data[0], 1);
        EXPECT_EQ(ip.data[1], 2);
        EXPECT_EQ(ip.data[2], 3);
        EXPECT_EQ(ip.data[3], 4);
    }

    {
        ddwaf::ipaddr ip{};
        EXPECT_TRUE(ddwaf::parse_ipv4("1.2.3.4", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4);
        EXPECT_EQ(ip.data[0], 1);
        EXPECT_EQ(ip.data[1], 2);
        EXPECT_EQ(ip.data[2], 3);
        EXPECT_EQ(ip.data[3], 4);
    }
}

TEST(TestIP, ParsingIPv4Class)
{
    ddwaf::ipaddr ip{};

    // Unless the system does, we don't support classfull IPs
    EXPECT_FALSE(ddwaf::parse_ip("1.257", ip));
}

TEST(TestIP, ParsingIPv6)
{
    {
        ddwaf::ipaddr ip{};

        EXPECT_TRUE(ddwaf::parse_ip("abcd::ef01", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
        EXPECT_EQ(ip.data[0], 0xab);
        EXPECT_EQ(ip.data[1], 0xcd);
        for (int i = 2; i < 14; ++i) { EXPECT_EQ(ip.data[i], 0); }

        EXPECT_EQ(ip.data[14], 0xef);
        EXPECT_EQ(ip.data[15], 0x01);
    }

    {
        ddwaf::ipaddr ip{};

        EXPECT_TRUE(ddwaf::parse_ipv6("abcd::ef01", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
        EXPECT_EQ(ip.data[0], 0xab);
        EXPECT_EQ(ip.data[1], 0xcd);
        for (int i = 2; i < 14; ++i) { EXPECT_EQ(ip.data[i], 0); }

        EXPECT_EQ(ip.data[14], 0xef);
        EXPECT_EQ(ip.data[15], 0x01);
    }
}

TEST(TestIP, ParsingIPv4MappedIPv6)
{
    {
        // Unfortunately inet_pton can't distinguish ipv4-mapped so the type is
        // IPv6 in this instance.
        ddwaf::ipaddr ip{};
        EXPECT_TRUE(ddwaf::parse_ip("0000:0000:0000:0000:0000:ffff:251.252.253.254", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
        for (int i = 0; i < 9; ++i) { EXPECT_EQ(ip.data[i], 0); }
        EXPECT_EQ(ip.data[10], 0xff);
        EXPECT_EQ(ip.data[11], 0xff);

        EXPECT_EQ(ip.data[12], 251);
        EXPECT_EQ(ip.data[13], 252);
        EXPECT_EQ(ip.data[14], 253);
        EXPECT_EQ(ip.data[15], 254);
    }

    {
        ddwaf::ipaddr ip{};
        EXPECT_TRUE(ddwaf::parse_ip("1.2.3.4", ip));
        ddwaf::ipv4_to_ipv6(ip);

        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);
        for (int i = 0; i < 9; ++i) { EXPECT_EQ(ip.data[i], 0); }
        EXPECT_EQ(ip.data[10], 0xff);
        EXPECT_EQ(ip.data[11], 0xff);

        EXPECT_EQ(ip.data[12], 0x01);
        EXPECT_EQ(ip.data[13], 0x02);
        EXPECT_EQ(ip.data[14], 0x03);
        EXPECT_EQ(ip.data[15], 0x04);
    }
}

TEST(TestIP, ParsingBadIP)
{
    ddwaf::ipaddr ip{};
    EXPECT_FALSE(ddwaf::parse_ip("not an IP", ip));
    EXPECT_FALSE(ddwaf::parse_ip("this is a very long string but not an IP"
                                 "unfortunately but that doesn't matter",
        ip));
}

TEST(TestIP, ParsingIPv4CIDR)
{
    ddwaf::ipaddr ip{};
    EXPECT_TRUE(ddwaf::parse_cidr("1.2.3.4/28", ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);

    // Check address
    for (int i = 0; i < 10; ++i) { EXPECT_EQ(ip.data[i], 0); }
    EXPECT_EQ(ip.data[10], 0xff);
    EXPECT_EQ(ip.data[11], 0xff);
    EXPECT_EQ(ip.data[12], 0x01);
    EXPECT_EQ(ip.data[13], 0x02);
    EXPECT_EQ(ip.data[14], 0x03);
    EXPECT_EQ(ip.data[15], 0x00);

    // Check mask
    EXPECT_EQ(ip.mask, 128 - 32 + 28);
}

TEST(TestIP, ParsingIPv4AsCIDR)
{
    {
        ddwaf::ipaddr ip{};
        EXPECT_TRUE(ddwaf::parse_cidr("1.2.3.4", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);

        // Check address
        for (int i = 0; i < 10; ++i) { EXPECT_EQ(ip.data[i], 0); }
        EXPECT_EQ(ip.data[10], 0xff);
        EXPECT_EQ(ip.data[11], 0xff);
        EXPECT_EQ(ip.data[12], 0x01);
        EXPECT_EQ(ip.data[13], 0x02);
        EXPECT_EQ(ip.data[14], 0x03);
        EXPECT_EQ(ip.data[15], 0x04);

        // Check mask
        EXPECT_EQ(ip.mask, 128);
    }

    {
        ddwaf::ipaddr ip{};
        EXPECT_TRUE(ddwaf::parse_cidr("1.2.3.4/1", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);

        // Check address
        for (int i = 0; i < 10; ++i) { EXPECT_EQ(ip.data[i], 0); }
        EXPECT_EQ(ip.data[10], 0xff);
        EXPECT_EQ(ip.data[11], 0xff);
        EXPECT_EQ(ip.data[12], 0x00);
        EXPECT_EQ(ip.data[13], 0x00);
        EXPECT_EQ(ip.data[14], 0x00);
        EXPECT_EQ(ip.data[15], 0x00);

        // Check mask
        EXPECT_EQ(ip.mask, 97);
    }

    {
        ddwaf::ipaddr ip{};
        EXPECT_TRUE(ddwaf::parse_cidr("1.3.3.4/15", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);

        // Check address
        for (int i = 0; i < 10; ++i) { EXPECT_EQ(ip.data[i], 0); }
        EXPECT_EQ(ip.data[10], 0xff);
        EXPECT_EQ(ip.data[11], 0xff);
        EXPECT_EQ(ip.data[12], 0x01);
        EXPECT_EQ(ip.data[13], 0x02);
        EXPECT_EQ(ip.data[14], 0x00);
        EXPECT_EQ(ip.data[15], 0x00);

        // Check mask
        EXPECT_EQ(ip.mask, 111);
    }
}

TEST(TestIP, ParsingIPv6CIDR)
{
    ddwaf::ipaddr ip{};
    EXPECT_TRUE(ddwaf::parse_cidr("aBcD::efff/121", ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);

    // Check address
    EXPECT_EQ(ip.data[0], 0xab);
    EXPECT_EQ(ip.data[1], 0xcd);
    for (int i = 2; i < 14; ++i) { EXPECT_EQ(ip.data[i], 0); }
    EXPECT_EQ(ip.data[15], 0x80);

    // Check mask
    EXPECT_EQ(ip.mask, 121);
}

TEST(TestIP, ParsingIPv4MappedIPv6CIDR)
{
    ddwaf::ipaddr ip{};
    EXPECT_TRUE(ddwaf::parse_cidr("0000:0000:0000:0000:0000:ffff:251.252.253.254/125", ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);

    // Check address
    for (int i = 0; i < 9; ++i) { EXPECT_EQ(ip.data[i], 0); }
    EXPECT_EQ(ip.data[10], 0xff);
    EXPECT_EQ(ip.data[11], 0xff);

    EXPECT_EQ(ip.data[12], 251);
    EXPECT_EQ(ip.data[13], 252);
    EXPECT_EQ(ip.data[14], 253);
    EXPECT_EQ(ip.data[15], 248);

    // Check mask
    EXPECT_EQ(ip.mask, 125);
}

TEST(TestIP, ParsingBadNetMask)
{
    ddwaf::ipaddr ip{};
    EXPECT_FALSE(ddwaf::parse_cidr("bad ip", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("1.2.3.4/", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("1.2.3.4/1234", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("1.2.3.4/33", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("::1/129", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("::1/a", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("::1/1291", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("not an IP/a", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("not an IP but also very very very very long/a", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("1.3.4.3/-1", ip));
    EXPECT_FALSE(ddwaf::parse_cidr("0000:0000:0000:0000:0000:ffff:251.252.253.2541/125", ip));
}

TEST(TestIP, ParsingIPv4Syntax)
{
    ddwaf::ipaddr ip{};

    EXPECT_TRUE(ddwaf::parse_ipv4("0.0.0.0", ip));
    EXPECT_TRUE(ddwaf::parse_ipv4("255.255.255.255", ip));
    EXPECT_EQ(ip.data[0], 255);
    EXPECT_EQ(ip.data[3], 255);
    EXPECT_TRUE(ddwaf::parse_ipv4("10.0.100.1", ip));
    EXPECT_EQ(ip.data[0], 10);
    EXPECT_EQ(ip.data[1], 0);
    EXPECT_EQ(ip.data[2], 100);
    EXPECT_EQ(ip.data[3], 1);

    for (auto bad : {"",           ".",         "1",         "1.2",      "1.2.3",     "1.2.3.",
                     ".1.2.3",     "1.2.3.4.",  "1.2.3.4.5", "1..2.3",   "256.1.1.1", "1.1.1.256",
                     "1000.1.1.1", "1.2.3.4 ",  " 1.2.3.4",  "1.2.3.a",  "0x1.2.3.4", "1.2.3.-4",
                     "+1.2.3.4",   "::1"}) {
        EXPECT_FALSE(ddwaf::parse_ipv4(bad, ip)) << bad;
    }

    // Leading zeros are rejected on every platform, although the inet_pton of
    // some platforms (e.g. macOS) accepts them; see
    // ParsingIgnoresPlatformLeniency
    for (auto bad : {"01.2.3.4", "1.2.3.04", "1.2.3.00"}) {
        EXPECT_FALSE(ddwaf::parse_ipv4(bad, ip)) << bad;
    }
}

TEST(TestIP, ParsingIPv6Syntax)
{
    auto parse = [](std::string_view str) -> std::optional<std::array<uint8_t, 16>> {
        ddwaf::ipaddr ip{};
        if (!ddwaf::parse_ipv6(str, ip)) {
            return std::nullopt;
        }
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
        EXPECT_EQ(ip.mask, 128);
        std::array<uint8_t, 16> bytes{};
        memcpy(bytes.data(), ip.data, bytes.size());
        return bytes;
    };
    using bytes = std::array<uint8_t, 16>;

    EXPECT_EQ(parse("::"), bytes{});
    EXPECT_EQ(parse("::1"), (bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}));
    EXPECT_EQ(parse("1::"), (bytes{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}));
    EXPECT_EQ(parse("1:2:3:4:5:6:7:8"), (bytes{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8}));
    EXPECT_EQ(parse("1:2:3:4:5:6:7::"), (bytes{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0}));
    EXPECT_EQ(parse("::2:3:4:5:6:7:8"), (bytes{0, 0, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8}));
    EXPECT_EQ(parse("1:2::7:8"), (bytes{0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 8}));
    EXPECT_EQ(parse("FfFf:0:00:000:0000:abcd:ABCD:aBcD"),
              (bytes{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd}));
    EXPECT_EQ(parse("::1.2.3.4"), (bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}));
    EXPECT_EQ(parse("::ffff:1.2.3.4"),
              (bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}));
    EXPECT_EQ(parse("1:2:3:4:5:6:1.2.3.4"),
              (bytes{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 1, 2, 3, 4}));
    EXPECT_EQ(parse("1::3:4:5:6:1.2.3.4"), (bytes{0, 1, 0, 0, 0, 3, 0, 4, 0, 5, 0, 6, 1, 2, 3, 4}));
    EXPECT_EQ(parse("1::6:255.0.0.1"), (bytes{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 255, 0, 0, 1}));

    for (auto bad : {"",
                     ":",
                     ":::",
                     "1",
                     "1:",
                     ":1",
                     "1:2",
                     "1::2::3",
                     "::1::",
                     "1:::2",
                     "1:2:3:4:5:6:7",
                     "1:2:3:4:5:6:7:8:9",
                     "1:2:3:4:5:6:7:8::",
                     "::1:2:3:4:5:6:7:8",
                     "1::2:3:4:5:6:7:8",
                     "12345::",
                     "::12345",
                     "g::",
                     "1:2:3:4:5:6:7:8:",
                     ":1:2:3:4:5:6:7:8",
                     "::1.2.3",
                     "::1.2.3.4.5",
                     "::1.2.3.256",
                     "::1.2.3.4:1",
                     "1.2.3.4::",
                     "1:2:3:4:5:6:7:1.2.3.4",
                     "1:2:3:4:5:6:7:8:1.2.3.4",
                     "1::3:4:5:6:7:1.2.3.4",
                     "::a.2.3.4",
                     "1.2.3.4",
                     ":: ",
                     " ::"}) {
        EXPECT_FALSE(parse(bad)) << bad;
    }

    // See ParsingIgnoresPlatformLeniency
    for (auto bad : {"::01.2.3.4", "::%eth0", "00001::"}) {
        EXPECT_FALSE(parse(bad)) << bad;
    }
}

// Addresses are parsed with the same rules on every platform, those of glibc's
// and musl's inet_pton, which cover the syntax the Datadog backend sends: the
// forms which only the more lenient inet_pton of macOS or Windows accepts
// (leading zeros in IPv4 octets, also in an embedded IPv4 address; IPv6 groups
// of more than four digits; a %zone suffix) are rejected everywhere, as they
// always were on Linux.
TEST(TestIP, ParsingIgnoresPlatformLeniency)
{
    for (const auto *str : {"01.2.3.4", "1.2.3.04", "1.2.3.00", "127.000.000.001", "010.0.0.1",
             "169.254.169.025", "00001::", "::ffff:010.0.0.1", "1:2:3:4:5:6:010.0.0.1",
             "::01.2.3.4", "2001:db8::5%en0", "::%eth0", "fe80::1%1"}) {
        ddwaf::ipaddr ip{};
        EXPECT_FALSE(ddwaf::parse_ipv4(str, ip)) << str;
        EXPECT_FALSE(ddwaf::parse_ipv6(str, ip)) << str;
        EXPECT_FALSE(ddwaf::parse_ip(str, ip)) << str;
        EXPECT_FALSE(ddwaf::parse_cidr(str, ip)) << str;
    }
}

// parse_ip tries IPv4 for inputs of up to 16 characters and IPv6 after that;
// 16 characters is one more than the longest dotted-decimal IPv4 address.
TEST(TestIP, ParsingSixteenCharacters)
{
    using namespace std::literals;
    ddwaf::ipaddr ip{};

    EXPECT_TRUE(ddwaf::parse_ip("2001:db8::1:2:34"sv, ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
    EXPECT_EQ(ip.data[0], 0x20);
    EXPECT_EQ(ip.data[1], 0x01);
    EXPECT_EQ(ip.data[13], 0x02);
    EXPECT_EQ(ip.data[14], 0x00);
    EXPECT_EQ(ip.data[15], 0x34);

    EXPECT_TRUE(ddwaf::parse_ip("::ffff:10.2.3.45"sv, ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
    EXPECT_EQ(ip.data[15], 45);

    EXPECT_TRUE(ddwaf::parse_cidr("2001:db8::1:2:34/128"sv, ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
    EXPECT_EQ(ip.mask, 128);

    for (auto str : {"0255.252.083.252"sv, "0106.156.251.252"sv, "255.255.255.2555"sv,
             "1255.255.255.255"sv, "255.255.255.255."sv, "255.255.255.255 "sv,
             "aaaaaaaaaaaaaaaa"sv, "2001:db8::1:2:3g"sv}) {
        ASSERT_EQ(str.size(), 16U) << str;
        EXPECT_FALSE(ddwaf::parse_ip(str, ip)) << str;
        EXPECT_FALSE(ddwaf::parse_ipv4(str, ip)) << str;
        EXPECT_FALSE(ddwaf::parse_ipv6(str, ip)) << str;
        EXPECT_FALSE(ddwaf::parse_cidr(str, ip)) << str;
    }

    // Not NUL-terminated: the characters after the view must not be read
    const std::string_view prefix = "1.2.3.4567890123x"sv.substr(0, 16);
    EXPECT_FALSE(ddwaf::parse_ip(prefix, ip));
    const std::string_view v6 = "2001:db8::1:2:34xyz"sv.substr(0, 16);
    EXPECT_TRUE(ddwaf::parse_ip(v6, ip));
    EXPECT_EQ(ip.data[15], 0x34);
}

TEST(TestIP, ParsingLengthLimits)
{
    ddwaf::ipaddr ip{};

    // 45 characters is the longest textual IPv6 address
    EXPECT_TRUE(ddwaf::parse_ip("0000:0000:0000:0000:0000:ffff:255.255.255.255", ip));
    EXPECT_TRUE(ddwaf::parse_ipv6("0000:0000:0000:0000:0000:ffff:255.255.255.255", ip));
    EXPECT_FALSE(ddwaf::parse_ip("00000:0000:0000:0000:0000:ffff:255.255.255.255", ip));
    EXPECT_FALSE(ddwaf::parse_ipv6("00000:0000:0000:0000:0000:ffff:255.255.255.255", ip));
}

TEST(TestIP, ParsingStopsAtNul)
{
    // The addresses used to be parsed from a NUL-terminated copy of the input
    using namespace std::literals;
    ddwaf::ipaddr ip{};

    EXPECT_TRUE(ddwaf::parse_ip("1.2.3.4\0garbage"sv, ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4);
    EXPECT_EQ(ip.data[3], 4);

    EXPECT_TRUE(ddwaf::parse_ipv4("1.2.3.5\0xyz"sv, ip));
    EXPECT_EQ(ip.data[3], 5);

    EXPECT_TRUE(ddwaf::parse_ipv6("::1\0xyz"sv, ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
    EXPECT_EQ(ip.data[15], 1);

    EXPECT_FALSE(ddwaf::parse_ip("\0001.2.3.4"sv, ip));
}

TEST(TestIP, ParseNetworkAgreesWithParseCidrOnBackendSyntax)
{
    // The forms the backend sends (netip.ParseAddr / netip.ParsePrefix syntax,
    // without zones)
    for (auto str : {"1.2.3.4", "0.0.0.0", "255.255.255.255", "1.2.3.4/32", "1.2.3.4/24",
             "10.0.0.0/8", "0.0.0.0/0", "203.0.113.0/24", "2001:db8::1", "2001:db8::/32",
             "::/0", "::", "::1", "::1/128", "fe80::/10", "2001:DB8:CAFE::/48",
             "2001:0db8:0000:0000:0000:0000:0000:0001", "1:2:3:4:5:6:7:8", "::ffff:1.2.3.4",
             "::ffff:1.2.3.0/120", "::ffff:0:0/96", "64:ff9b::1.2.3.4", "1.2.3.4/0",
             "abcd:ef01:2345:6789:abcd:ef01:2345:6789/127", "2001:db8::1:2:34",
             "2001:db8::1:2:34/64", "::ffff:10.2.3.45"}) {
        ddwaf::ipaddr expected{};
        ddwaf::ipaddr ip{};
        ASSERT_TRUE(ddwaf::parse_cidr(str, expected)) << str;
        ASSERT_TRUE(ddwaf::parse_network(str, ip)) << str;
        EXPECT_EQ(memcmp(ip.data, expected.data, sizeof(ip.data)), 0) << str;
        EXPECT_EQ(ip.mask, expected.mask) << str;
        EXPECT_EQ(ip.type, expected.type) << str;
    }

    // Prefix lengths with leading zeros are still accepted
    ddwaf::ipaddr ip{};
    EXPECT_TRUE(ddwaf::parse_network("1.2.3.4/08", ip));
    EXPECT_EQ(ip.mask, 96 + 8);
    EXPECT_EQ(ip.data[13], 0);
    EXPECT_TRUE(ddwaf::parse_network("::1/000", ip));
    EXPECT_EQ(ip.mask, 0);
}

TEST(TestIP, ParseNetworkRejectsWhatParseCidrRejects)
{
    for (auto str : {"", "bad ip", "1.2.3", "1.2.3.4/", "/8", "1.2.3.4/33", "::1/129", "::1/a",
             "1.2.3.4/1234", "::1/1291", "01.2.3.4", "256.1.1.1", "1.2.3.4.5", ":::",
             "12345::", "1.2.3.4 ", " 1.2.3.4", "fe80::1%eth0", "fe80::1%eth0/64"}) {
        ddwaf::ipaddr ip{};
        EXPECT_FALSE(ddwaf::parse_cidr(str, ip)) << str;
        EXPECT_FALSE(ddwaf::parse_network(str, ip)) << str;
    }
}

TEST(TestIP, ParseNetworkStricterThanParseCidr)
{
    // parse_cidr reads the prefix length with std::stoi and the address up to
    // a NUL character; the backend never sends these forms
    using namespace std::literals;
    for (auto str : {"1.2.3.4/+8"sv, "1.2.3.4/ 8"sv, "1.2.3.4/8 "sv, "1.2.3.4/8a"sv,
             "1.2.3.4/-0"sv, "1.2.3.4/8/"sv, "::1/\t64"sv, "1.2.3.4\0junk"sv,
             "1.2.3.4\0/8"sv}) {
        ddwaf::ipaddr ip{};
        EXPECT_TRUE(ddwaf::parse_cidr(str, ip)) << str;
        EXPECT_FALSE(ddwaf::parse_network(str, ip)) << str;
    }
}

} // namespace
