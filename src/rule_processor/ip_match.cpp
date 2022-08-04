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
            radix_put_if_absent(rtree_.get(), &prefix);
        }
    }

}

std::optional<event::match> ip_match::match(std::string_view str) const
{
    if (str.empty() || str.data() == nullptr) {
        return {};
    }

    ddwaf::ipaddr ip;
    if (!ddwaf::parse_ip(str, ip)) {
        return {};
    }

    // Convert the IPv4 to IPv6
    ddwaf::ipv4_to_ipv6(ip);

    // Initialize the radix structure to check if the IP exist
    prefix_t radix_ip;
    radix_prefix_init(FAMILY_IPv6, ip.data, 128, &radix_ip);

    // Run the check
    if (!radix_matching_do(rtree_.get(), &radix_ip)) {
        return {};
    }

    return make_event(str, str);
}

}
