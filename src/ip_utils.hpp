// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdint>
#include <string_view>

namespace ddwaf {

// TODO: Make parsing functions static from_* methods returning an ipaddr and
//       throw exceptions on errors.
//       Don't automatically generate mapped IPv6 addresses.
struct ipaddr {
    uint8_t data[16]; // big endian
    uint8_t mask;
    enum class address_family {
        ipv4,
        ipv6,
        ipv4_mapped_ipv6,
    } type;
};

bool parse_ip(std::string_view ip, ipaddr &out);
bool parse_ipv4(std::string_view ip, ipaddr &out);
bool parse_ipv6(std::string_view ip, ipaddr &out);
void ipv4_to_ipv6(ipaddr &out);
bool parse_cidr(std::string_view str, ipaddr &out);

// Parses an IP address or network in the syntax the Datadog backend sends for
// IP rules and exclusion data (ip_with_expiration): an IPv4 address in
// dotted-decimal notation or an IPv6 address (as accepted by parse_ipv4 and
// parse_ipv6), optionally followed by '/' and a prefix length of one to three
// decimal digits, at most 32 or 128. IPv4 networks are converted to
// IPv4-mapped IPv6 and the host bits are cleared, as with parse_cidr.
//
// Unlike parse_cidr, it does not accept the following, which the backend
// never sends: a prefix length with a sign, whitespace or trailing characters
// (std::stoi syntax), and a NUL character ending the address.
bool parse_network(std::string_view str, ipaddr &out);

} // namespace ddwaf
