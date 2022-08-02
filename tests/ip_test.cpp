// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestIP, ParsingIPv4)
{
    ddwaf::ipaddr ip;
    EXPECT_TRUE(ddwaf::parse_ip("1.2.3.4", ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4);
    EXPECT_EQ(ip.data[0], 1);
    EXPECT_EQ(ip.data[1], 2);
    EXPECT_EQ(ip.data[2], 3);
    EXPECT_EQ(ip.data[3], 4);
}

TEST(TestIP, ParsingIPv4Class)
{
    ddwaf::ipaddr ip;

    // Unless the system does, we don't support classfull IPs
    EXPECT_FALSE(ddwaf::parse_ip("1.257", ip));
}

TEST(TestIP, ParsingIPv6)
{
    ddwaf::ipaddr ip;

    EXPECT_TRUE(ddwaf::parse_ip("abcd::ef01", ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
    EXPECT_EQ(ip.data[0], 0xab);
    EXPECT_EQ(ip.data[1], 0xcd);
    for(int i = 2; i < 14; ++i) {
        EXPECT_EQ(ip.data[i], 0);
    }

    EXPECT_EQ(ip.data[14], 0xef);
    EXPECT_EQ(ip.data[15], 0x01);
}

TEST(TestIP, ParsingIPv4MappedIPv6)
{
    {
        // Unfortunately inet_pton can't distinguish ipv4-mapped so the type is
        // IPv6 in this instance.
        ddwaf::ipaddr ip;
        EXPECT_TRUE(ddwaf::parse_ip("0000:0000:0000:0000:0000:ffff:251.252.253.254", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);
        for(int i = 0; i < 9; ++i) {
            EXPECT_EQ(ip.data[i], 0);
        }
        EXPECT_EQ(ip.data[10], 0xff);
        EXPECT_EQ(ip.data[11], 0xff);

        EXPECT_EQ(ip.data[12], 251);
        EXPECT_EQ(ip.data[13], 252);
        EXPECT_EQ(ip.data[14], 253);
        EXPECT_EQ(ip.data[15], 254);
    }

    {
        ddwaf::ipaddr ip;
        EXPECT_TRUE(ddwaf::parse_ip("1.2.3.4", ip));
        ddwaf::ipv4_to_ipv6(ip);

        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);
        for(int i = 0; i < 9; ++i) {
            EXPECT_EQ(ip.data[i], 0);
        }
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
    ddwaf::ipaddr ip;
    EXPECT_FALSE(ddwaf::parse_ip("not an IP", ip));
    EXPECT_FALSE(ddwaf::parse_ip("this is a very long string but not an IP"
        "unfortunately but that doesn't matter", ip));
}

TEST(TestIP, ParsingIPv4CIDR)
{
    ddwaf::ipaddr ip;
    EXPECT_TRUE(ddwaf::parse_cidr("1.2.3.4/28", ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);

    // Check address
    for(int i = 0; i < 10; ++i)
    {
        EXPECT_EQ(ip.data[i], 0);
    }
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
        ddwaf::ipaddr ip;
        EXPECT_TRUE(ddwaf::parse_cidr("1.2.3.4", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);

        // Check address
        for(int i = 0; i < 10; ++i)
        {
            EXPECT_EQ(ip.data[i], 0);
        }
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
        ddwaf::ipaddr ip;
        EXPECT_TRUE(ddwaf::parse_cidr("1.2.3.4/1", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);

        // Check address
        for(int i = 0; i < 10; ++i)
        {
            EXPECT_EQ(ip.data[i], 0);
        }
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
        ddwaf::ipaddr ip;
        EXPECT_TRUE(ddwaf::parse_cidr("1.3.3.4/15", ip));
        EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv4_mapped_ipv6);

        // Check address
        for(int i = 0; i < 10; ++i)
        {
            EXPECT_EQ(ip.data[i], 0);
        }
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
    ddwaf::ipaddr ip;
    EXPECT_TRUE(ddwaf::parse_cidr("aBcD::efff/121", ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);

    // Check address
    EXPECT_EQ(ip.data[0], 0xab);
    EXPECT_EQ(ip.data[1], 0xcd);
    for(int i = 2; i < 14; ++i) {
        EXPECT_EQ(ip.data[i], 0);
    }
    EXPECT_EQ(ip.data[15], 0x80);

    // Check mask
    EXPECT_EQ(ip.mask, 121);
}

TEST(TestIP, ParsingIPv4MappedIPv6CIDR)
{
    ddwaf::ipaddr ip;
    EXPECT_TRUE(ddwaf::parse_cidr("0000:0000:0000:0000:0000:ffff:251.252.253.254/125", ip));
    EXPECT_EQ(ip.type, ddwaf::ipaddr::address_family::ipv6);

    // Check address
    for(int i = 0; i < 9; ++i) {
        EXPECT_EQ(ip.data[i], 0);
    }
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
    ddwaf::ipaddr ip;
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
