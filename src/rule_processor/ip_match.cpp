// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule_processor/ip_match.hpp>
#include <ip_utils.hpp>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <iostream>

namespace ddwaf::rule_processor
{

ip_match::ip_match(const std::vector<std::string_view> &ip_list):
    rtree_(radix_new(128), radix_free) // Allocate the radix tree in IPv6 mode
{
    if (!rtree_) {
        throw std::runtime_error("failed to instantiate radix tree");
    }

    for (auto str : ip_list) {
        // Parse and populate each IP/network
        ipaddr ip;
        if (ddwaf::parse_cidr(str, ip)) {
            prefix_t prefix;
            radix_prefix_init(FAMILY_IPv6, ip.data, ip.mask, &prefix);
            auto node = radix_put_if_absent(rtree_.get(), &prefix);
            node->expiration = 0;
        }
    }
}

ip_match::ip_match(const std::vector<std::pair<std::string_view,uint64_t>> &ip_list):
    rtree_(radix_new(128), radix_free) // Allocate the radix tree in IPv6 mode
{
    if (!rtree_) {
        throw std::runtime_error("failed to instantiate radix tree");
    }

    for (auto [str, expiration] : ip_list) {
        // Parse and populate each IP/network
        ipaddr ip;
        if (ddwaf::parse_cidr(str, ip)) {
            prefix_t prefix;
            radix_prefix_init(FAMILY_IPv6, ip.data, ip.mask, &prefix);
            auto node = radix_put_if_absent(rtree_.get(), &prefix);
            node->expiration = expiration;
        }
    }
}

std::optional<event::match> ip_match::match(std::string_view str) const
{
    if (!rtree_ || str.empty() || str.data() == nullptr) {
        return std::nullopt;
    }

    ddwaf::ipaddr ip;
    if (!ddwaf::parse_ip(str, ip)) {
        return std::nullopt;
    }

    // Convert the IPv4 to IPv6
    ddwaf::ipv4_to_ipv6(ip);

    // Initialize the radix structure to check if the IP exist
    prefix_t radix_ip;
    radix_prefix_init(FAMILY_IPv6, ip.data, 128, &radix_ip);

    // Run the check
    auto node = radix_matching_do(rtree_.get(), &radix_ip);
    if (node == nullptr) {
        return std::nullopt;
    }

    if (node->expiration > 0) {
        uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (node->expiration < now) {
            return std::nullopt;
        }
    }

    return make_event(str, str);
}

}
