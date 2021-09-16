// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "IPWRuleProcessor.h"
#include <utils.h>

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

PROD_STATIC bool parseIP(const char* ipString, parsed_ip& parsed)
{
    int ret = inet_pton(AF_INET, ipString, &parsed.ip);
    if (ret != 1)
    {
        ret = inet_pton(AF_INET6, ipString, &parsed.ip);
        if (ret != 1)
        {
            return false;
        }
        else
        {
            parsed.isIPv6 = true;
        }
    }
    else
    {
        parsed.isIPv6 = false;
    }
    return true;
}

static void ipv4ToIpv6(parsed_ip& parsed)
{
    if (!parsed.isIPv6)
    {
        // The first four indexes contain the IPv4
        // We want to turn them into an IPv6 using the following format:
        // 1.2.3.4 -> ::ffff:1.2.3.4

        parsed.ip[10] = 0xff;
        parsed.ip[11] = 0xff;

        parsed.ip[12] = parsed.ip[0];
        parsed.ip[13] = parsed.ip[1];
        parsed.ip[14] = parsed.ip[2];
        parsed.ip[15] = parsed.ip[3];

        memset(parsed.ip, 0, 10);
    }
}

PROD_STATIC bool parseCIDR(const char* ipString, size_t stringLength, prefix_t& prefix)
{
    // Find the position of the slash in order to hide it from the PoV of parseIP
    parsed_ip parsedIP;
    uint8_t bitLength    = 128;
    const char* slashPtr = static_cast<const char*>(memchr(ipString, '/', stringLength));

    // Do we have a subnet?
    if (slashPtr != NULL)
    {
        const size_t indexSlash = static_cast<size_t>(slashPtr - ipString);

        // Not a valid IP
        if (indexSlash > 40)
            return false;

        // Not a valid netmask (/ at the end or for than 3 digits at the end)
        if (indexSlash + 1 == stringLength || stringLength - indexSlash > 4)
            return false;

        // Parse the IP
        char zeroTerminatedIP[41] = { 0 };
        memcpy(zeroTerminatedIP, ipString, indexSlash);
        if (!parseIP(zeroTerminatedIP, parsedIP))
            return false;

        // Great, now parse the netmask
        uint16_t tmpBitLength = 0;
        for (size_t i = indexSlash + 1; i < stringLength; ++i)
        {
            if (!isdigit(ipString[i]))
                return false;

            tmpBitLength *= 10;
            tmpBitLength += ipString[i] - '0';
        }

        if (!parsedIP.isIPv6)
            tmpBitLength += (128 - 32);

        if (tmpBitLength > 128)
            return false;

        bitLength = (uint8_t) tmpBitLength;
    }
    else
    {
        //Simpler!
        if (!parseIP(ipString, parsedIP))
            return false;
    }

    ipv4ToIpv6(parsedIP);

    // Zero the masked bits if we have a mask
    uint8_t indexStartMask = bitLength / 8;
    if (indexStartMask < 16)
    {
        // Mask the lower bits of the first masked byte (we want to keep some of them)
        // if bitLength & 0x7 == 2, we want to keep the top two bits (& 0x7 <=> % 8)
        // Therefore, we take 0xff and shift it by 2 (resulting in 0011_1111)
        // We then flip the bits (resulting in 1100_0000) and use that as a mask
        parsedIP.ip[indexStartMask] &= ~(0xff >> (bitLength & 0x7));

        while (++indexStartMask < 16)
            parsedIP.ip[indexStartMask] = 0;
    }

    radix_prefix_init(FAMILY_IPv6, parsedIP.ip, bitLength, &prefix);
    return true;
}

bool IPMatch::performMatch(const char* patternValue, size_t patternLength, MatchGatherer& gatherer) const
{
    // The maximum IPv6 length is of 39 characters. We add one for shenanigans around 0-terminated in the input
    if (patternValue == NULL || patternLength == 0 || patternLength > 40 || radixTree == nullptr)
    {
        return false;
    }

    // Copy the IP so that we're sure that the buffer is zero-terminated
    char zeroTerminatedIP[41] = { 0 };
    memcpy(zeroTerminatedIP, patternValue, patternLength);

    parsed_ip structuredIP;
    if (!parseIP(zeroTerminatedIP, structuredIP))
    {
        return false;
    }

    // Convert the IPv4 to IPv6
    ipv4ToIpv6(structuredIP);

    // Initialize the radix structure to check if the IP exist
    prefix_t radixIP;
    radix_prefix_init(FAMILY_IPv6, structuredIP.ip, 128, &radixIP);

    // Run the check
    bool didMatch   = radix_matching_do(radixTree, &radixIP);
    bool didSucceed = didMatch == wantMatch;

    if (didSucceed)
    {
        gatherer.resolvedValue = std::string(patternValue, patternLength);
        if (didMatch)
        {
            gatherer.matchedValue = gatherer.resolvedValue;
        }
    }

    return didSucceed;
}

IPMatch::~IPMatch()
{
    if (radixTree)
        radix_free(radixTree);
}

bool IPMatch::buildProcessor(const rapidjson::Value& value, bool)
{
    if (!value.IsArray() || radixTree != NULL)
    {
        return false;
    }

    // Allocate the radix tree in IPv6 mode
    radixTree = radix_new(128);

    if (radixTree != NULL)
    {
        for (const auto& item : value.GetArray())
        {
            if (!item.IsString())
            {
                radix_free(radixTree);
                radixTree = NULL;
                break;
            }

            // Parse and populate each IP/network
            prefix_t prefix;
            if (parseCIDR(item.GetString(), item.GetStringLength(), prefix))
            {
                radix_put_if_absent(radixTree, &prefix);
            }
        }
    }

    return radixTree != NULL;
}
