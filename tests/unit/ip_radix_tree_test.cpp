// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "ip_radix_tree.hpp"
#include "ip_utils.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

ipaddr cidr(std::string_view str)
{
    ipaddr ip{};
    EXPECT_TRUE(parse_cidr(str, ip)) << str;
    return ip;
}

ipaddr address(std::string_view str)
{
    ipaddr ip{};
    EXPECT_TRUE(parse_ip(str, ip)) << str;
    ipv4_to_ipv6(ip);
    return ip;
}

ip_radix_tree build(const std::vector<std::pair<std::string_view, uint64_t>> &networks)
{
    ip_radix_tree::builder builder;
    for (const auto &[str, expiration] : networks) { builder.insert(cidr(str), expiration); }
    return builder.build();
}

std::optional<uint64_t> find(const ip_radix_tree &table, std::string_view str)
{
    return table.find(address(str));
}

TEST(TestIPRadixTree, Empty)
{
    auto table = ip_radix_tree::builder{}.build();
    EXPECT_TRUE(table.empty());
    EXPECT_EQ(table.node_count(), 0);
    EXPECT_FALSE(find(table, "1.2.3.4"));
    EXPECT_FALSE(find(table, "::"));

    ip_radix_tree default_table;
    EXPECT_TRUE(default_table.empty());
    EXPECT_FALSE(find(default_table, "1.2.3.4"));
}

TEST(TestIPRadixTree, SingleAddresses)
{
    auto table = build({{"1.2.3.4", 0}, {"1.2.3.6", 10}, {"::1", 20}, {"ffff::ffff", 0}});

    EXPECT_EQ(find(table, "1.2.3.4"), 0);
    EXPECT_FALSE(find(table, "1.2.3.3"));
    EXPECT_FALSE(find(table, "1.2.3.5"));
    EXPECT_EQ(find(table, "1.2.3.6"), 10);
    EXPECT_FALSE(find(table, "1.2.3.7"));
    EXPECT_FALSE(find(table, "::"));
    EXPECT_EQ(find(table, "::1"), 20);
    EXPECT_FALSE(find(table, "::2"));
    EXPECT_EQ(find(table, "ffff::ffff"), 0);
    EXPECT_FALSE(find(table, "ffff::fffe"));
    EXPECT_FALSE(find(table, "ffff::1:0"));
}

TEST(TestIPRadixTree, NetworkBoundaries)
{
    auto table = build({{"10.0.0.0/8", 5}, {"2001:db8::/32", 7}, {"abcd::/64", 9}});

    EXPECT_FALSE(find(table, "9.255.255.255"));
    EXPECT_EQ(find(table, "10.0.0.0"), 5);
    EXPECT_EQ(find(table, "10.255.255.255"), 5);
    EXPECT_FALSE(find(table, "11.0.0.0"));

    EXPECT_FALSE(find(table, "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"));
    EXPECT_EQ(find(table, "2001:db8::"), 7);
    EXPECT_EQ(find(table, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), 7);
    EXPECT_FALSE(find(table, "2001:db9::"));

    EXPECT_FALSE(find(table, "abcc:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    EXPECT_EQ(find(table, "abcd::"), 9);
    EXPECT_EQ(find(table, "abcd::ffff:ffff:ffff:ffff"), 9);
    EXPECT_FALSE(find(table, "abcd:0:0:1::"));
}

TEST(TestIPRadixTree, HostBitsIgnored)
{
    ipaddr network = address("10.1.2.3");
    network.mask = 96 + 16;

    ip_radix_tree::builder builder;
    builder.insert(network, 0);
    auto table = builder.build();

    EXPECT_FALSE(find(table, "10.0.255.255"));
    EXPECT_EQ(find(table, "10.1.0.0"), 0);
    EXPECT_EQ(find(table, "10.1.255.255"), 0);
    EXPECT_FALSE(find(table, "10.2.0.0"));
}

TEST(TestIPRadixTree, WholeAddressSpace)
{
    auto table =
        build({{"::/0", 100}, {"1.2.3.4", 200}, {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 50}});

    EXPECT_EQ(find(table, "::"), 100);
    EXPECT_EQ(find(table, "1.2.3.3"), 100);
    EXPECT_EQ(find(table, "1.2.3.4"), 200);
    EXPECT_EQ(find(table, "1.2.3.5"), 100);
    EXPECT_EQ(find(table, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), 100);
    EXPECT_EQ(find(table, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 100);
    // ::/0 in the IPv6 tree, 1.2.3.4 alone in the IPv4 tree, and the last
    // address below ::/0
    EXPECT_EQ(table.node_count(), 3);
    // IPv6 nodes take 28 bytes, IPv4 nodes 16
    EXPECT_EQ(table.memory_usage(), (2 * 28) + 16);
}

TEST(TestIPRadixTree, NestedNetworksLatestExpirationWins)
{
    auto table = build({
        {"1.0.0.0/8", 10},
        {"1.2.0.0/16", 20},
        {"1.2.3.0/24", 15},
        {"1.2.3.4", 30},
        {"2.0.0.0/8", 0},
        {"2.2.2.2", 5},
        {"3.0.0.0/8", 5},
        {"3.3.0.0/16", 0},
        {"3.3.3.3", 7},
    });

    EXPECT_EQ(find(table, "1.1.1.1"), 10);
    EXPECT_EQ(find(table, "1.2.1.1"), 20);
    EXPECT_EQ(find(table, "1.2.3.3"), 20);
    EXPECT_EQ(find(table, "1.2.3.4"), 30);
    EXPECT_EQ(find(table, "1.2.3.5"), 20);
    EXPECT_EQ(find(table, "1.2.4.0"), 20);
    EXPECT_EQ(find(table, "1.3.0.0"), 10);

    EXPECT_EQ(find(table, "2.2.2.2"), 0);
    EXPECT_EQ(find(table, "2.2.2.3"), 0);

    EXPECT_EQ(find(table, "3.2.0.0"), 5);
    EXPECT_EQ(find(table, "3.3.3.3"), 0);
    EXPECT_EQ(find(table, "3.3.255.255"), 0);
    EXPECT_EQ(find(table, "3.4.0.0"), 5);
    EXPECT_FALSE(find(table, "4.0.0.0"));
}

TEST(TestIPRadixTree, NetworksSharingBoundaries)
{
    // Nested networks starting or ending at the same address as their parent,
    // and adjacent networks
    auto table = build({
        {"10.0.0.0/8", 10},
        {"10.0.0.0/16", 20},
        {"10.255.0.0/16", 30},
        {"10.255.255.255", 40},
        {"11.0.0.0/8", 10},
        {"12.0.0.0/8", 50},
    });

    EXPECT_EQ(find(table, "10.0.0.0"), 20);
    EXPECT_EQ(find(table, "10.0.255.255"), 20);
    EXPECT_EQ(find(table, "10.1.0.0"), 10);
    EXPECT_EQ(find(table, "10.254.255.255"), 10);
    EXPECT_EQ(find(table, "10.255.0.0"), 30);
    EXPECT_EQ(find(table, "10.255.255.254"), 30);
    EXPECT_EQ(find(table, "10.255.255.255"), 40);
    EXPECT_EQ(find(table, "11.0.0.0"), 10);
    EXPECT_EQ(find(table, "11.255.255.255"), 10);
    EXPECT_EQ(find(table, "12.0.0.0"), 50);
    EXPECT_EQ(find(table, "12.255.255.255"), 50);
    EXPECT_FALSE(find(table, "13.0.0.0"));
    EXPECT_FALSE(find(table, "9.255.255.255"));
}

TEST(TestIPRadixTree, Duplicates)
{
    auto table = build({
        {"1.1.1.1", 10},
        {"1.1.1.1", 30},
        {"1.1.1.1", 20},
        {"2.2.2.2", 0},
        {"2.2.2.2", 10},
        {"3.3.3.3", 10},
        {"3.3.3.3", 0},
        {"4.0.0.0/8", 10},
        {"4.0.0.0/8", 20},
        {"4.4.4.4", 15},
    });

    EXPECT_EQ(find(table, "1.1.1.1"), 30);
    EXPECT_EQ(find(table, "2.2.2.2"), 0);
    EXPECT_EQ(find(table, "3.3.3.3"), 0);
    EXPECT_EQ(find(table, "4.4.4.4"), 20);
    EXPECT_EQ(find(table, "4.4.4.5"), 20);
}

TEST(TestIPRadixTree, InsertionOrderIrrelevant)
{
    std::vector<std::pair<std::string_view, uint64_t>> networks{
        {"1.0.0.0/8", 10},
        {"1.2.3.4", 30},
        {"1.2.0.0/16", 20},
        {"abcd::/16", 0},
        {"abcd:1::/32", 5},
        {"::ffff:0:0/96", 1},
    };

    auto forward = build(networks);
    std::reverse(networks.begin(), networks.end());
    auto backward = build(networks);

    EXPECT_EQ(forward.node_count(), backward.node_count());
    for (auto ip : {"0.0.0.0", "1.0.0.0", "1.2.3.3", "1.2.3.4", "1.2.3.5", "1.3.0.0", "2.0.0.0",
             "abcd::", "abcd:1::1", "abcd:2::", "abce::", "::fffe:ffff:ffff"}) {
        EXPECT_EQ(find(forward, ip), find(backward, ip)) << ip;
    }
    EXPECT_EQ(find(forward, "1.2.3.4"), 30);
    EXPECT_EQ(find(forward, "2.0.0.0"), 1);
    EXPECT_EQ(find(forward, "abcd:1::1"), 0);
    EXPECT_FALSE(find(forward, "::fffe:ffff:ffff"));
}

TEST(TestIPRadixTree, GlueNodes)
{
    // 10.0.0.0/9 and 10.128.0.0/9 are joined by a glue node at /8, whose
    // address is not a network
    auto table = build({{"10.0.0.0/9", 0}, {"10.128.0.0/9", 0}, {"10.1.0.0/16", 0}});
    EXPECT_EQ(table.node_count(), 4);
    EXPECT_EQ(table.memory_usage(), 4 * 16);
    EXPECT_EQ(find(table, "10.0.0.0"), 0);
    EXPECT_EQ(find(table, "10.127.255.255"), 0);
    EXPECT_EQ(find(table, "10.128.0.0"), 0);
    EXPECT_EQ(find(table, "10.255.255.255"), 0);
    EXPECT_FALSE(find(table, "11.0.0.0"));
    EXPECT_FALSE(find(table, "9.255.255.255"));

    // A network later inserted at the position of a glue node replaces it
    auto with_glue_network =
        build({{"10.0.0.0/9", 5}, {"10.128.0.0/9", 5}, {"10.0.0.0/8", 7}, {"10.1.2.3", 3}});
    EXPECT_EQ(with_glue_network.node_count(), 4);
    EXPECT_EQ(find(with_glue_network, "10.0.0.0"), 7);
    EXPECT_EQ(find(with_glue_network, "10.1.2.3"), 7);
    EXPECT_EQ(find(with_glue_network, "10.200.0.0"), 7);
    EXPECT_FALSE(find(with_glue_network, "11.0.0.0"));
}

TEST(TestIPRadixTree, SearchStopsAtDivergingNode)
{
    // The root is a glue node, 1.2.3.0/24, joining the two /25 networks; the
    // search for an address outside it stops there
    auto table = build({{"1.2.3.0/25", 10}, {"1.2.3.128/25", 20}, {"1.2.3.4", 30}});
    EXPECT_EQ(find(table, "1.2.3.4"), 30);
    EXPECT_EQ(find(table, "1.2.3.5"), 10);
    EXPECT_EQ(find(table, "1.2.3.200"), 20);
    EXPECT_FALSE(find(table, "1.2.4.4"));
    EXPECT_FALSE(find(table, "1.2.2.4"));
    EXPECT_FALSE(find(table, "129.2.3.4"));
}

TEST(TestIPRadixTree, LargeExpirations)
{
    auto table = build({{"1.0.0.0/8", uint64_t{1} << 53}, {"1.1.1.1", 1}, {"2.2.2.2", 4102444800},
        {"3.3.3.3", UINT64_MAX - 1}, {"4.4.4.4", uint64_t{1} << 54}});
    EXPECT_EQ(find(table, "1.1.1.1"), uint64_t{1} << 53);
    EXPECT_EQ(find(table, "1.2.3.4"), uint64_t{1} << 53);
    EXPECT_EQ(find(table, "2.2.2.2"), 4102444800);
    // Expirations of 2^54 - 1 seconds (500 million years) or later are kept
    // as "never expires"
    EXPECT_EQ(find(table, "3.3.3.3"), 0);
    EXPECT_EQ(find(table, "4.4.4.4"), 0);
}

TEST(TestIPRadixTree, PreorderLayout)
{
    // Every node has a left child, a right child, both or none; the lookups
    // cover every kind of step
    auto table = build({
        {"128.0.0.0/1", 1},
        {"192.0.0.0/2", 2},
        {"160.0.0.0/3", 3},
        {"10.0.0.0/8", 4},
        {"10.0.0.0/16", 5},
        {"10.255.0.0/16", 6},
        {"10.1.0.0/16", 7},
        {"11.0.0.0/8", 8},
    });
    EXPECT_EQ(find(table, "128.0.0.1"), 1);
    EXPECT_EQ(find(table, "192.0.0.1"), 2);
    EXPECT_EQ(find(table, "160.0.0.1"), 3);
    EXPECT_EQ(find(table, "10.2.0.0"), 4);
    EXPECT_EQ(find(table, "10.0.0.1"), 5);
    EXPECT_EQ(find(table, "10.255.0.1"), 6);
    EXPECT_EQ(find(table, "10.1.0.1"), 7);
    EXPECT_EQ(find(table, "11.1.0.1"), 8);
    EXPECT_FALSE(find(table, "12.0.0.0"));
    EXPECT_FALSE(find(table, "9.0.0.0"));
    EXPECT_FALSE(find(table, "127.255.255.255"));
}

TEST(TestIPRadixTree, IPv4MappedAndIPv6NetworksInterleaved)
{
    // IPv6 networks containing (parts of) the IPv4-mapped range, IPv4 networks
    // and IPv4-mapped networks written in IPv6 notation
    auto table = build({
        {"::/64", 10},
        {"::ffff:0:0/96", 20},
        {"::ffff:0:0/100", 30},
        {"0.0.0.0/8", 25},
        {"::ffff:10.0.0.0/104", 40},
        {"10.1.0.0/16", 35},
        {"::ffff:10.1.2.3", 50},
        {"::1:0:0:0", 60},
        {"255.255.255.255", 70},
    });

    EXPECT_EQ(find(table, "::"), 10);
    EXPECT_EQ(find(table, "::fffe:ffff:ffff"), 10);
    EXPECT_EQ(find(table, "0.0.0.0"), 30);
    EXPECT_EQ(find(table, "0.255.255.255"), 30);
    EXPECT_EQ(find(table, "10.0.0.1"), 40);
    EXPECT_EQ(find(table, "10.1.0.0"), 40);
    EXPECT_EQ(find(table, "10.1.2.3"), 50);
    EXPECT_EQ(find(table, "10.255.255.255"), 40);
    EXPECT_EQ(find(table, "15.255.255.255"), 30);
    EXPECT_EQ(find(table, "16.0.0.0"), 20);
    EXPECT_EQ(find(table, "255.255.255.254"), 20);
    EXPECT_EQ(find(table, "255.255.255.255"), 70);
    EXPECT_EQ(find(table, "::1:0:0:0"), 60);
    EXPECT_EQ(find(table, "::1:0:0:1"), 10);
    EXPECT_EQ(find(table, "::1:ffff:ffff:ffff"), 10);
    EXPECT_FALSE(find(table, "0:0:0:1::"));
}

TEST(TestIPRadixTree, ManyDuplicates)
{
    ip_radix_tree::builder builder;
    for (uint64_t i = 1; i <= 1000; ++i) {
        builder.insert(cidr("1.0.0.0/8"), 1000 + (i * 7919) % 1000);
        builder.insert(cidr("1.2.3.4"), 500);
        builder.insert(cidr("abcd::/16"), i);
    }
    builder.insert(cidr("1.2.0.0/16"), 0);
    auto table = builder.build();

    EXPECT_EQ(find(table, "1.0.0.0"), 1999);
    EXPECT_EQ(find(table, "1.2.0.0"), 0);
    EXPECT_EQ(find(table, "1.2.3.4"), 0);
    EXPECT_EQ(find(table, "1.3.0.0"), 1999);
    EXPECT_EQ(find(table, "abcd::1"), 1000);
    EXPECT_FALSE(find(table, "2.0.0.0"));
}

} // namespace
