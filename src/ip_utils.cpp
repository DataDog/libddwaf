// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <ip_utils.hpp>
#include <cstring>

#if defined(_WIN32) || defined(__MINGW32__)

#if defined(__MINGW32__) || defined(_WIN32_WINNT)
// Mingw is messing with the NT version
// https://github.com/msys2/MINGW-packages/issues/6191
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x600
#endif

#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace ddwaf {

bool parse_ip(const char* str, ipaddr& parsed)
{
    parsed.type = ipaddr::address_family::ipv4;
    int ret = inet_pton(AF_INET, str, &parsed.data);
    if (ret != 1) {
        ret = inet_pton(AF_INET6, str, &parsed.data);
        if (ret != 1) {
            return false;
        }
        parsed.type = ipaddr::address_family::ipv6;
    }
    return true;
}

void ipv4_to_ipv6(ipaddr& parsed)
{
    if (parsed.type == ipaddr::address_family::ipv4) {
        // The first four indexes contain the IPv4
        // We want to turn them into an IPv6 using the following format:
        // 1.2.3.4 -> ::ffff:1.2.3.4

        parsed.data[10] = 0xff;
        parsed.data[11] = 0xff;

        parsed.data[12] = parsed.data[0];
        parsed.data[13] = parsed.data[1];
        parsed.data[14] = parsed.data[2];
        parsed.data[15] = parsed.data[3];

        memset(parsed.data, 0, 10);
    }
}

bool parse_cidr(const char* str, size_t length, prefix_t& prefix)
{
    // Find the position of the slash in order to hide it from the PoV of parseIP
    ipaddr parsedIP;
    uint8_t bitLength    = 128;
    const char* slashPtr = static_cast<const char*>(memchr(str, '/', length));

    // Do we have a subnet?
    if (slashPtr != NULL) {
        const size_t indexSlash = static_cast<size_t>(slashPtr - str);

        // Not a valid IP
        if (indexSlash > 40) {
            return false;
        }

        // Not a valid netmask (/ at the end or for than 3 digits at the end)
        if (indexSlash + 1 == length || length - indexSlash > 4) { return false; }

        // Parse the IP
        char zeroTerminatedIP[41] = { 0 };
        memcpy(zeroTerminatedIP, str, indexSlash);
        if (!parse_ip(zeroTerminatedIP, parsedIP)) { return false; }

        // Great, now parse the netmask
        uint16_t tmpBitLength = 0;
        for (size_t i = indexSlash + 1; i < length; ++i)
        {
            if (!isdigit(str[i])) { return false; }

            tmpBitLength *= 10;
            tmpBitLength += str[i] - '0';
        }

        if (parsedIP.type != ipaddr::address_family::ipv6) {
            tmpBitLength += (128 - 32);
        }

        if (tmpBitLength > 128) { return false; }

        bitLength = (uint8_t) tmpBitLength;
    } else {
        //Simpler!
        if (!parse_ip(str, parsedIP)) { return false; }
    }

    ipv4_to_ipv6(parsedIP);

    // Zero the masked bits if we have a mask
    uint8_t indexStartMask = bitLength / 8;
    if (indexStartMask < 16) {
        // Mask the lower bits of the first masked byte (we want to keep some of them)
        // if bitLength & 0x7 == 2, we want to keep the top two bits (& 0x7 <=> % 8)
        // Therefore, we take 0xff and shift it by 2 (resulting in 0011_1111)
        // We then flip the bits (resulting in 1100_0000) and use that as a mask
        parsedIP.data[indexStartMask] &= ~(0xff >> (bitLength & 0x7));

        while (++indexStartMask < 16) {
            parsedIP.data[indexStartMask] = 0;
        }
    }

    radix_prefix_init(FAMILY_IPv6, parsedIP.data, bitLength, &prefix);
    return true;
}

}
