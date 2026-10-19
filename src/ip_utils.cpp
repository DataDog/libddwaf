// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

#include "ip_utils.hpp"

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
namespace ddwaf {

namespace {

// The address parsers below replace inet_pton, which requires a NUL-terminated
// copy of the input and is comparatively slow (e.g. it accounted for about a
// tenth of the time of loading a large IP blocklist). They accept the syntax the
// Datadog backend sends (rules and exclusion data are validated with Go's
// netip.ParseAddr and netip.ParsePrefix): dotted-decimal IPv4 addresses without
// leading zeros, and RFC 4291 IPv6 addresses, possibly ending in an IPv4 part.
// These are the rules of glibc's and musl's inet_pton, and they apply on every
// platform: the more lenient inet_pton of macOS and Windows (e.g. leading zeros
// in IPv4 octets, a %zone suffix) is not reproduced, for request addresses
// either. A NUL character terminates the address, as it did when the input was
// copied into a C string.

// Sizes of the C string buffers previously used with inet_pton
// (INET_ADDRSTRLEN and INET6_ADDRSTRLEN, both including the terminating NUL),
// which remain the length limits of the textual addresses.
constexpr std::size_t ipv4_str_size = 16;
constexpr std::size_t ipv6_str_size = 46;

std::string_view until_nul(std::string_view str)
{
    auto nul = str.find('\0');
    return nul == std::string_view::npos ? str : str.substr(0, nul);
}

int hex_digit_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

// Dotted-decimal IPv4 address: exactly four decimal octets in [0, 255], without
// leading zeros.
bool pton4(std::string_view src, uint8_t *dst)
{
    std::array<uint8_t, 4> octets{};
    std::size_t count = 0;
    unsigned value = 0;
    bool saw_digit = false;

    for (const char c : src) {
        if (c >= '0' && c <= '9') {
            if (saw_digit && value == 0) {
                return false; // leading zero
            }
            value = value * 10 + static_cast<unsigned>(c - '0');
            if (value > 255) {
                return false;
            }
            if (!saw_digit) {
                if (++count > 4) {
                    return false;
                }
                saw_digit = true;
            }
        } else if (c == '.' && saw_digit) {
            if (count == 4) {
                return false;
            }
            octets[count - 1] = static_cast<uint8_t>(value);
            value = 0;
            saw_digit = false;
        } else {
            return false;
        }
    }

    if (count < 4 || !saw_digit) {
        return false;
    }
    octets[3] = static_cast<uint8_t>(value);

    memcpy(dst, octets.data(), octets.size());
    return true;
}

// IPv6 address (RFC 4291 section 2.2): eight groups of one to four hex digits
// separated by colons, where one run of zero groups may be replaced by "::"
// (which must stand for at least one group) and the last two groups may be
// written as a dotted-decimal IPv4 address.
bool pton6(std::string_view src, uint8_t *dst)
{
    std::array<uint8_t, 16> tmp{};
    std::size_t tp = 0;
    std::optional<std::size_t> colonp; // position of "::", if any
    std::size_t i = 0;

    if (src.empty()) {
        return false;
    }

    // A leading colon must be part of "::"
    if (src[0] == ':') {
        if (src.size() < 2 || src[1] != ':') {
            return false;
        }
        i = 1;
    }

    std::size_t curtok = i;
    std::size_t xdigits_seen = 0;
    unsigned value = 0;
    while (i < src.size()) {
        const char c = src[i++];
        const int digit = hex_digit_value(c);
        if (digit >= 0) {
            if (xdigits_seen == 4) {
                return false;
            }
            value = (value << 4) | static_cast<unsigned>(digit);
            ++xdigits_seen;
            continue;
        }

        if (c == ':') {
            curtok = i;
            if (xdigits_seen == 0) {
                if (colonp.has_value()) {
                    return false;
                }
                colonp = tp;
                continue;
            }
            if (i == src.size() || tp + 2 > tmp.size()) {
                return false;
            }
            tmp[tp++] = static_cast<uint8_t>(value >> 8);
            tmp[tp++] = static_cast<uint8_t>(value & 0xff);
            xdigits_seen = 0;
            value = 0;
            continue;
        }

        // An embedded IPv4 address takes the rest of the string
        if (c == '.' && tp + 4 <= tmp.size() && pton4(src.substr(curtok), &tmp[tp])) {
            tp += 4;
            xdigits_seen = 0;
            break;
        }

        return false;
    }

    if (xdigits_seen > 0) {
        if (tp + 2 > tmp.size()) {
            return false;
        }
        tmp[tp++] = static_cast<uint8_t>(value >> 8);
        tmp[tp++] = static_cast<uint8_t>(value & 0xff);
    }

    if (colonp.has_value()) {
        // "::" must stand for at least one group
        if (tp == tmp.size()) {
            return false;
        }
        // Move the groups after "::" to the end, and zero the gap
        const std::size_t tail = tp - *colonp;
        std::memmove(tmp.data() + (tmp.size() - tail), tmp.data() + *colonp, tail);
        std::memset(&tmp[*colonp], 0, tmp.size() - tail - *colonp);
        tp = tmp.size();
    }

    if (tp != tmp.size()) {
        return false;
    }

    memcpy(dst, tmp.data(), tmp.size());
    return true;
}

bool parse_ipv4_internal(std::string_view ip, ipaddr &out)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    if (!pton4(until_nul(ip), out.data)) {
        return false;
    }

    out.type = ipaddr::address_family::ipv4;
    out.mask = 32;
    return true;
}

bool parse_ipv6_internal(std::string_view ip, ipaddr &out)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    if (!pton6(until_nul(ip), out.data)) {
        return false;
    }

    out.type = ipaddr::address_family::ipv6;
    out.mask = 128;
    return true;
}

// Clears the bits of the address beyond its prefix length (mask)
void clear_host_bits(ipaddr &out)
{
    uint8_t byte_index = out.mask / 8;
    if (byte_index < 16) {
        // Mask the lower bits of the first masked byte (we want to keep some of them)
        // if bitLength & 0x7 == 2, we want to keep the top two bits (& 0x7 <=> % 8)
        // Therefore, we take 0xff and shift it by 2 (resulting in 0011_1111)
        // We then flip the bits (resulting in 1100_0000) and use that as a mask
        out.data[byte_index] &= ~(0xff >> (out.mask & 0x7));

        while (++byte_index < 16) { out.data[byte_index] = 0; }
    }
}

} // namespace

bool parse_ip(std::string_view ip, ipaddr &out)
{
    if (ip.size() >= ipv6_str_size) {
        return false;
    }

    if (ip.size() > ipv4_str_size || !parse_ipv4_internal(ip, out)) {
        return parse_ipv6_internal(ip, out);
    }

    return true;
}

bool parse_ipv4(std::string_view ip, ipaddr &out)
{
    if (ip.size() >= ipv4_str_size) {
        return false;
    }

    return parse_ipv4_internal(ip, out);
}

bool parse_ipv6(std::string_view ip, ipaddr &out)
{
    if (ip.size() >= ipv6_str_size) {
        return false;
    }

    return parse_ipv6_internal(ip, out);
}

void ipv4_to_ipv6(ipaddr &out)
{
    if (out.type != ipaddr::address_family::ipv4) {
        return;
    }

    // The first four indexes contain the IPv4
    // We want to turn them into an IPv6 using the following format:
    // 1.2.3.4 -> ::ffff:1.2.3.4
    out.data[10] = 0xff;
    out.data[11] = 0xff;

    out.data[12] = out.data[0];
    out.data[13] = out.data[1];
    out.data[14] = out.data[2];
    out.data[15] = out.data[3];

    memset(&out.data[0], 0, 10);

    out.mask += 96;
    out.type = ipaddr::address_family::ipv4_mapped_ipv6;
}

bool parse_cidr(std::string_view str, ipaddr &out)
{
    auto slash_idx = str.find('/');
    if (slash_idx != std::string_view::npos) {
        if (slash_idx >= ipv6_str_size) {
            return false;
        }

        auto mask_len = str.size() - slash_idx - 1;
        if (mask_len == 0 || mask_len > 3) {
            return false;
        }

        if (!parse_ip(str.substr(0, slash_idx), out)) {
            return false;
        }

        int mask;
        try {
            mask = std::stoi(std::string(str.substr(slash_idx + 1, mask_len)));
        } catch (...) {
            return false;
        }

        if ((out.type == ipaddr::address_family::ipv4 && mask > 32) ||
            (out.type == ipaddr::address_family::ipv6 && mask > 128) || mask < 0) {
            return false;
        }

        out.mask = static_cast<uint8_t>(mask);
    } else {
        if (!parse_ip(str, out)) {
            return false;
        }
    }

    ipv4_to_ipv6(out);
    clear_host_bits(out);
    return true;
}

bool parse_network(std::string_view str, ipaddr &out)
{
    const auto slash_idx = str.find('/');
    const std::string_view address = str.substr(0, slash_idx);

    unsigned max_prefix_len;
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    if (pton4(address, out.data)) {
        out.type = ipaddr::address_family::ipv4;
        max_prefix_len = 32;
    } else if (pton6(address, out.data)) {
        out.type = ipaddr::address_family::ipv6;
        max_prefix_len = 128;
    } else {
        return false;
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)

    unsigned prefix_len = max_prefix_len;
    if (slash_idx != std::string_view::npos) {
        const std::string_view digits = str.substr(slash_idx + 1);
        if (digits.empty() || digits.size() > 3) {
            return false;
        }
        prefix_len = 0;
        for (const char c : digits) {
            if (c < '0' || c > '9') {
                return false;
            }
            prefix_len = prefix_len * 10 + static_cast<unsigned>(c - '0');
        }
        if (prefix_len > max_prefix_len) {
            return false;
        }
    }
    out.mask = static_cast<uint8_t>(prefix_len);

    ipv4_to_ipv6(out);
    clear_host_bits(out);
    return true;
}

} // namespace ddwaf
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
