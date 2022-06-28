// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include <utils.h>

uint8_t codepointToUTF8(uint32_t codepoint, char* utf8Buffer)
{
    //Handle the easy case of ASCII
    if (codepoint <= 0x7F)
    {
        *utf8Buffer = (char) codepoint;
        return 1;
    }

    /*
     You're reading the UTF-8 encoding code, I'm sorry.
     There are multiple representations depending of the codepoint:
     0x000000-0x00007F: 0xxxxxxx
     0x000080-0x0007FF: 110xxxxx 10xxxxxx
     0x000800-0x00FFFF: 1110xxxx 10xxxxxx 10xxxxxx
     0x010000-0x10FFFF: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
     This code could be made a bit denser but let's not look for trouble
     */

    // Out of range codepoint
    if (codepoint > 0x001FFFFF)
        return 0;

    //4 bytes representation
    if (codepoint > 0xFFFF)
    {
        *utf8Buffer++ = (char) (0xF0 | ((codepoint >> 18) & 0x08));
        *utf8Buffer++ = (char) (0x80 | ((codepoint >> 12) & 0x3F));
        *utf8Buffer++ = (char) (0x80 | ((codepoint >> 06) & 0x3F));
        *utf8Buffer++ = (char) (0x80 | (codepoint & 0x3F));
        return 4;
    }
    // Three bytes
    else if (codepoint > 0x7FF)
    {
        *utf8Buffer++ = (char) (0xE0 | ((codepoint >> 12) & 0x0F));
        *utf8Buffer++ = (char) (0x80 | ((codepoint >> 06) & 0x3F));
        *utf8Buffer++ = (char) (0x80 | (codepoint & 0x3F));
        return 3;
    }
    // Two bytes
    else
    {
        *utf8Buffer++ = (char) (0xC0 | ((codepoint >> 06) & 0x0F));
        *utf8Buffer++ = (char) (0x80 | (codepoint & 0x3F));
        return 2;
    }
}

uint8_t writeCodePoint(uint32_t codepoint, char* utf8Buffer, uint64_t lengthLeft)
{
    //  If null, a surrogate or larger than the allowed range, buzz off
    if (codepoint == 0 || (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
    {
        // Insert U+FFFD as an error character per-spec
        //  We need three bytes to encode it, which may be a problem as `\0` only takes two
        //  A fully correct implementation would make room for the error bytes if there isn't enough room but we won't bother with that
        if (lengthLeft > 2)
        {
            *((uint8_t*) utf8Buffer++) = 0xEFu;
            *((uint8_t*) utf8Buffer++) = 0xBFu;
            *((uint8_t*) utf8Buffer++) = 0xBDu;
            return 3;
        }

        return 0;
    }

    //TODO: Perform normalization

    // Insert the bytes
    return codepointToUTF8(codepoint, utf8Buffer);
}
