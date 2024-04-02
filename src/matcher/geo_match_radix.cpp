// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string_view>

#include "country_codes.hpp"
#include "matcher/geo_match_radix.hpp"

namespace ddwaf::matcher {

geo_match_radix::geo_match_radix(std::unordered_set<std::string_view> countries,
    const std::vector<std::pair<std::string_view, std::string_view>> &ip_list)
    : rtree_(radix_new(radix_tree_bits), radix_free)
{
    if (!rtree_) {
        throw std::runtime_error("failed to instantiate radix tree");
    }

    countries_.reserve(countries.size());
    for (auto &code : countries) {
        auto index = country_code_to_index(code);
        if (index == 0) {
            continue;
        }
        countries_.emplace(index);
    }

    for (auto [str, code] : ip_list) {
        // Parse and populate each IP/network
        ipaddr ip{};
        if (ddwaf::parse_cidr(str, ip)) {
            auto index = country_code_to_index(code);
            if (index == 0) {
                continue;
            }

            prefix_t prefix;
            // NOLINTNEXTLINE(hicpp-no-array-decay,cppcoreguidelines-pro-bounds-array-to-pointer-decay)
            radix_prefix_init(FAMILY_IPv6, ip.data, ip.mask, &prefix);
            auto *node = radix_put_if_absent(rtree_.get(), &prefix, 0);
            if (node == nullptr) {
                continue;
            }
            node->iso_code = index;
        }
    }
}

[[nodiscard]] bool geo_match_radix::match_ip(const ipaddr &ip) const
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

    return countries_.contains(node->iso_code);
}

std::pair<bool, std::string> geo_match_radix::match_impl(std::string_view str) const
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
