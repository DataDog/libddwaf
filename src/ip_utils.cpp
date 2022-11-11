// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cctype>
#include <cstring>
#include <ip_utils.hpp>
#include <netinet/in.h>
#include <string>

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
#if defined(_WIN32) || defined(__MINGW32__)

#  if defined(__MINGW32__) || defined(_WIN32_WINNT)
// Mingw is messing with the NT version
// https://github.com/msys2/MINGW-packages/issues/6191
#    undef _WIN32_WINNT
#    define _WIN32_WINNT 0x600
#  endif

#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif

namespace ddwaf {

bool parse_ip(std::string_view ip, ipaddr &out)
{
    if (ip.size() >= INET6_ADDRSTRLEN) {
        return false;
    }

    // Assume the string has no '\0'
    //char ip_cstr[INET6_ADDRSTRLEN] = {0};
    std::array<char, INET6_ADDRSTRLEN> ip_cstr{0};

    memcpy(ip_cstr.data(), ip.data(), ip.size());

    int ret = inet_pton(AF_INET, ip_cstr.data(), &out.data);
    if (ret != 1) {
        ret = inet_pton(AF_INET6, ip_cstr.data(), &out.data);
        if (ret != 1) {
            return false;
        }
        out.type = ipaddr::address_family::ipv6;
        out.mask = 128;
    } else {
        out.type = ipaddr::address_family::ipv4;
        out.mask = 32;
    }
    return true;
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
        if (slash_idx >= INET6_ADDRSTRLEN) {
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

    // Zero the masked bits if we have a mask
    uint8_t byte_index = out.mask / 8;
    if (byte_index < 16) {
        // Mask the lower bits of the first masked byte (we want to keep some of them)
        // if bitLength & 0x7 == 2, we want to keep the top two bits (& 0x7 <=> % 8)
        // Therefore, we take 0xff and shift it by 2 (resulting in 0011_1111)
        // We then flip the bits (resulting in 1100_0000) and use that as a mask
        out.data[byte_index] &= ~(0xff >> (out.mask & 0x7));

        while (++byte_index < 16) { out.data[byte_index] = 0; }
    }

    return true;
}

} // namespace ddwaf
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
