// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <utils.h>

size_t find_string_cutoff(const char *str, size_t length, uint32_t max_string_length)
{
    //If the string is shorter than our cap, then fine
    if (length <= max_string_length)
        return length;

    //If it's longer, we need to truncate it. However, we don't want to cut a UTF-8 byte sequence in the middle of it!
    //Valid UTF8 has a specific binary format.
    //	If it's a single byte UTF8 character, then it is always of form '0xxxxxxx', where 'x' is any binary digit.
    //	If it's a two byte UTF8 character, then it's always of form '110xxxxx 10xxxxxx'.
    //	Similarly for three and four byte UTF8 characters it starts with '1110xxxx' and '11110xxx' followed
    //		by '10xxxxxx' one less times as there are bytes.

    //We take the two strongest bits of the first trimmed character. We have four possibilities:
    // - 00 or 01: single UTF-8 byte, no risk trimming
    // - 11: New multi-byte sequence, we can ignore it, no risk trimming
    // - 10: Middle of multi byte sequence, we need to step back
    // We therefore loop as long as we see the '10' sequence

    size_t pos = max_string_length;
    while (pos != 0 && (str[pos] & 0xC0) == 0x80)
    {
        pos -= 1;
    }

    return pos;
}
