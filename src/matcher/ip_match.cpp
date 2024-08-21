// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <chrono>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ip_utils.hpp"
#include "matcher/ip_match.hpp"
#include "radixlib.h"

namespace ddwaf::matcher {

ip_match::ip_match(const std::vector<std::string_view> &ip_list)
    : rtree_(radix_new(radix_tree_bits), radix_free)
{
    if (!rtree_) {
        throw std::runtime_error("failed to instantiate radix tree");
    }

    init_tree(ip_list);
}

ip_match::ip_match(const std::vector<std::pair<std::string_view, uint64_t>> &ip_list)
    : rtree_(radix_new(radix_tree_bits), radix_free)
{
    if (!rtree_) {
        throw std::runtime_error("failed to instantiate radix tree");
    }

    for (auto [str, expiration] : ip_list) {
        // Parse and populate each IP/network
        ipaddr ip{};
        if (ddwaf::parse_cidr(str, ip)) {
            prefix_t prefix;
            // NOLINTNEXTLINE(hicpp-no-array-decay,cppcoreguidelines-pro-bounds-array-to-pointer-decay)
            radix_prefix_init(FAMILY_IPv6, ip.data, ip.mask, &prefix);
            radix_put_if_absent(rtree_.get(), &prefix, expiration);
        }
    }
}

[[nodiscard]] bool ip_match::match_ip(const ipaddr &ip) const
{
    // Initialize the radix structure to check if the IP exist
    prefix_t radix_ip;
    // NOLINTNEXTLINE(hicpp-no-array-decay,cppcoreguidelines-pro-bounds-array-to-pointer-decay,
    // cppcoreguidelines-pro-type-const-cast)
    radix_prefix_init(FAMILY_IPv6, const_cast<uint8_t *>(ip.data), radix_tree_bits, &radix_ip);

    // Run the check
    auto *node = radix_matching_do(rtree_.get(), &radix_ip);
    if (node == nullptr) {
        return false;
    }

    if (node->expiration > 0) {
        const uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
                                 .count();
        if (node->expiration < now) {
            return false;
        }
    }

    return true;
}

std::pair<bool, std::string> ip_match::match_impl(std::string_view str) const
{
    if (!rtree_ || str.empty() || str.data() == nullptr) {
        return {false, {}};
    }

    ddwaf::ipaddr ip{};
    if (!ddwaf::parse_ip(str, ip)) {
        return {false, {}};
    }
    // Convert the IPv4 to IPv6
    ddwaf::ipv4_to_ipv6(ip);

    if (!match_ip(ip)) {
        return {false, {}};
    }

    return {true, std::string{str}};
}

} // namespace ddwaf::matcher
