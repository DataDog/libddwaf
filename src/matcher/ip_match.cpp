// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dynamic_string.hpp"
#include "expiring_string_list.hpp"
#include "indexed_multivector.hpp"
#include "ip_range_table.hpp"
#include "ip_utils.hpp"
#include "matcher/ip_match.hpp"

namespace ddwaf::matcher {

ip_match::ip_match(const std::vector<std::string_view> &ip_list) : table_(build_table(ip_list)) {}

ip_match::ip_match(
    const indexed_multivector<std::string, std::pair<std::string, uint64_t>> &ip_list)
    : table_(build_table(ip_list))
{}

ip_match::ip_match(const indexed_multivector<std::string, expiring_string_list::value_type,
    expiring_string_list> &ip_list)
    : table_(build_table(ip_list))
{}

ip_match::ip_match(const std::vector<std::pair<std::string, uint64_t>> &ip_list)
    : table_(build_table(ip_list))
{}

[[nodiscard]] bool ip_match::match_ip(const ipaddr &ip) const
{
    auto expiration = table_.find(ip);
    if (!expiration.has_value()) {
        return false;
    }

    if (*expiration > 0) {
        const uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
                                 .count();
        if (*expiration < now) {
            return false;
        }
    }

    return true;
}

std::pair<bool, dynamic_string> ip_match::match_impl(std::string_view str) const
{
    if (table_.empty() || str.empty() || str.data() == nullptr) {
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
