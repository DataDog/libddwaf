// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule_processor/ip_match.hpp>
#include <ip_utils.hpp>
#include <cstring>
#include <stdexcept>

namespace ddwaf::rule_processor
{

ip_match::ip_match(const std::vector<std::string> &ip_list):
    rtree_(radix_new(128), radix_free) // Allocate the radix tree in IPv6 mode
{
    if (!rtree_) {
        throw std::runtime_error("failed to instantiate radix tree");
    }

    for (const auto &ip : ip_list) {
        // Parse and populate each IP/network
        prefix_t prefix;
        if (ddwaf::parse_cidr(ip.c_str(), ip.size(), prefix)) {
            radix_put_if_absent(rtree_.get(), &prefix);
        }
    }

}

bool ip_match::match(const char* str, size_t length, MatchGatherer& gatherer) const
{
    // The maximum IPv6 length is of 39 characters. We add one for shenanigans around 0-terminated in the input
    if (str == NULL || length == 0 || length > 40) {
        return false;
    }

    // Copy the IP so that we're sure that the buffer is zero-terminated
    char zeroTerminatedIP[41] = { 0 };
    memcpy(zeroTerminatedIP, str, length);

    ddwaf::ipaddr structuredIP;
    if (!ddwaf::parse_ip(zeroTerminatedIP, structuredIP)) {
        return false;
    }

    // Convert the IPv4 to IPv6
    ddwaf::ipv4_to_ipv6(structuredIP);

    // Initialize the radix structure to check if the IP exist
    prefix_t radixIP;
    radix_prefix_init(FAMILY_IPv6, structuredIP.data, 128, &radixIP);

    // Run the check
    if (!radix_matching_do(rtree_.get(), &radixIP)) {
        return false;
    }

    gatherer.resolvedValue = std::string(str, length);
    gatherer.matchedValue = gatherer.resolvedValue;

    return true;
}

}
