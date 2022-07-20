// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"
#include <radixlib.h>

bool parseIP(const char* ipString, parsed_ip& parsed);
bool parseCIDR(const char* ipString, size_t stringLength, prefix_t& prefix);

TEST(TestIP, ParsingIPv4)
{
   parsed_ip ip;

    EXPECT_TRUE(parseIP("1.2.3.4", ip));
    EXPECT_FALSE(ip.isIPv6);
    EXPECT_EQ(ip.ip[0], 1);
    EXPECT_EQ(ip.ip[1], 2);
    EXPECT_EQ(ip.ip[2], 3);
    EXPECT_EQ(ip.ip[3], 4);
}

TEST(TestIP, ParsingIPv4Class)
{
    parsed_ip ip;

    //// Unless the system does, we don't support classfull IPs
    EXPECT_FALSE(parseIP("1.257", ip));
}

TEST(TestIP, ParsingIPv6)
{
    parsed_ip ip;

    EXPECT_TRUE(parseIP("abcd::ef01", ip));
    EXPECT_TRUE(ip.isIPv6);
    EXPECT_EQ(ip.ip[0], 0xab);
    EXPECT_EQ(ip.ip[1], 0xcd);
    for(int i = 2; i < 14; ++i)
    EXPECT_EQ(ip.ip[i], 0);

    EXPECT_EQ(ip.ip[14], 0xef);
    EXPECT_EQ(ip.ip[15], 0x01);
}

TEST(TestIP, ParsingBadIP)
{
    parsed_ip ip;
    EXPECT_FALSE(parseIP("not an IP", ip));
}

TEST(TestIP, ParsingIPv4CIDR)
{
    prefix_t ip;
    EXPECT_TRUE(parseCIDR("1.2.3.4/28", strlen("1.2.3.4/28"), ip));
    EXPECT_EQ(ip.family, FAMILY_IPv6);

    // Check address
    for(int i = 0; i < 10; ++i)
    {
    EXPECT_EQ(ip.add.sin6[i], 0);
    }
    EXPECT_EQ(ip.add.sin6[10], 0xff);
    EXPECT_EQ(ip.add.sin6[11], 0xff);
    EXPECT_EQ(ip.add.sin6[12], 0x01);
    EXPECT_EQ(ip.add.sin6[13], 0x02);
    EXPECT_EQ(ip.add.sin6[14], 0x03);
    EXPECT_EQ(ip.add.sin6[15], 0x00);

    // Check mask
    EXPECT_EQ(ip.bitlen, 128 - 32 + 28);
}

TEST(TestIP, ParsingIPv4AsCIDR)
{
    prefix_t ip;
    EXPECT_TRUE(parseCIDR("1.2.3.4", strlen("1.2.3.4"), ip));
    EXPECT_EQ(ip.family, FAMILY_IPv6);

    // Check address
    for(int i = 0; i < 10; ++i)
    {
    EXPECT_EQ(ip.add.sin6[i], 0);
    }
    EXPECT_EQ(ip.add.sin6[10], 0xff);
    EXPECT_EQ(ip.add.sin6[11], 0xff);
    EXPECT_EQ(ip.add.sin6[12], 0x01);
    EXPECT_EQ(ip.add.sin6[13], 0x02);
    EXPECT_EQ(ip.add.sin6[14], 0x03);
    EXPECT_EQ(ip.add.sin6[15], 0x04);

    // Check mask
    EXPECT_EQ(ip.bitlen, 128);
}

TEST(TestIP, ParsingIPv6CIDR)
{
    prefix_t ip;
    EXPECT_TRUE(parseCIDR("aBcD::efff/121", strlen("aBcD::efff/120"), ip));
    EXPECT_EQ(ip.family, FAMILY_IPv6);

    // Check address
    EXPECT_EQ(ip.add.sin6[0], 0xab);
    EXPECT_EQ(ip.add.sin6[1], 0xcd);
    for(int i = 2; i < 14; ++i)
    EXPECT_EQ(ip.add.sin6[i], 0);
    EXPECT_EQ(ip.add.sin6[15], 0x80);

    // Check mask
    EXPECT_EQ(ip.bitlen, 121);
}

TEST(TestIP, ParsingBadNetMask)
{
    prefix_t ip;
    EXPECT_FALSE(parseCIDR("bad ip", strlen("bad ip"), ip));
    EXPECT_FALSE(parseCIDR("1.2.3.4/", strlen("1.2.3.4/"), ip));
    EXPECT_FALSE(parseCIDR("1.2.3.4/1234", strlen("1.2.3.4/1234"), ip));
    EXPECT_FALSE(parseCIDR("1.2.3.4/33", strlen("1.2.3.4/33"), ip));
    EXPECT_FALSE(parseCIDR("::1/129", strlen("::1/129"), ip));
    EXPECT_FALSE(parseCIDR("::1/a", strlen("::1/a"), ip));
    EXPECT_FALSE(parseCIDR("not an IP/a", strlen("not an IP/a"), ip));
    EXPECT_FALSE(parseCIDR("not an IP but also very very very very long/a", strlen("not an IP but also very very very very long/a"), ip));
}
