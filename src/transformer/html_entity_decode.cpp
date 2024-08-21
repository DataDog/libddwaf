// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <cstdint>

#include "transformer/common/cow_string.hpp"
#include "transformer/common/utf8.hpp"
#include "transformer/html_entity_decode.hpp"
#include "utils.hpp"

namespace ddwaf::transformer {
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
namespace {
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
bool replace_if_match(cow_string &str, size_t &read, size_t &write, const char *token,
    size_t token_length, char decoded)
{
    const size_t remaining = str.length() - read;
    if (remaining < token_length) {
        return false;
    }

    // Case incensitive match (assume the token is lowercase)
    for (size_t pos = 0; pos < token_length; ++pos) {
        if ((str.at(read + pos) | 0x20) != *token++) {
            return false;
        }
    }

    str[write++] = decoded;
    read += token_length;

    return true;
}
// NOLINTEND(bugprone-easily-swappable-parameters)
} // namespace

bool html_entity_decode::transform_impl(cow_string &str)
{
    // If the string is too short
    if (str.length() < 3) {
        return false;
    }

    // There are three kinds of escape in HTML:
    //   &#XXXXX; where XX are numerical digits
    //   &#xYYY; or &#XYYY; where YYY is an hex-encoded codepoint
    //   &ZZZZ; where ZZZZ is an alphanumerical name for the character
    //  In practice, the semicolon is optional

    // We skip ahead looking for a `&`. That's not enough to know for sure if we need to
    // edit but it's a decent shortcut nonetheless
    size_t read = 0;
    for (; read < str.length() && str.at(read) != '&'; ++read) {}

    size_t write = read;
    while (read < str.length()) {
        if (str.at(read) != '&' || read == str.length() - 1) {
            str.copy_char(read++, write++);
            continue;
        }

        read += 1; // Skip the &
        // Codepoint
        if (str.at(read) == '#') {
            read += 1; // Skip the #

            uint32_t codePoint = 0;

            // Hexadecimal codepoint
            if (read < str.length() - 1 && (str.at(read) == 'x' || str.at(read) == 'X') &&
                ddwaf::isxdigit(str.at(read + 1))) {
                read += 1; // Skip the x

                // Compute the codepoint. We need to compute an arbitrary number of hex
                // chars because browsers do too :(
                while (read < str.length() && ddwaf::isxdigit(str.at(read))) {
                    codePoint <<= 4;
                    codePoint |= ddwaf::from_hex(str.at(read++));

                    // If we go out of range, move the read head to the end and abort
                    // immediately. We don't want to risk an overflow
                    if (codePoint > 0x10ffff) {
                        for (; read < str.length() && ddwaf::isxdigit(str.at(read)); read += 1) {}
                    }
                }
            }
            // Numeric codepoint
            else if (read < str.length() && ddwaf::isdigit(str.at(read))) {
                // Compute the codepoint. We need to compute an arbitrary number of digits
                // because browsers do too :(
                while (read < str.length() && ddwaf::isdigit(str.at(read))) {
                    codePoint *= 10;
                    codePoint += (uint32_t)str.at(read++) - '0';

                    // If we go out of range, move the read head to the end and abort
                    // immediately. We don't want to risk an overflow
                    if (codePoint > 0x10ffff) {
                        for (; read < str.length() && ddwaf::isdigit(str.at(read)); read += 1) {}
                    }
                }
            }
            // Accidental match
            else {
                str.copy_char(read - 2, write++);
                str.copy_char(read - 1, write++);
                continue;
            }

            // We extracted the codepoint (or bailed out). Now, we can transcribe it
            write += ddwaf::utf8::write_codepoint(codePoint, &str[write], read - write);

            if (read < str.length() && str.at(read) == ';') {
                read += 1;
            }
        }
        // Named character references
        else if (ddwaf::isalnum(str.at(read))) {
            // Try to decode a few known references
            if (!replace_if_match(str, read, write, "lt;", 3, '<') &&
                !replace_if_match(str, read, write, "gt;", 3, '>') &&
                !replace_if_match(str, read, write, "amp;", 4, '&') &&
                !replace_if_match(str, read, write, "quot;", 5, '"') &&
                !replace_if_match(str, read, write, "nbsp;", 5, (char)160)) {
                // If none work, write the & we skipped
                str.copy_char(read - 1, write++);
            }
        } else {
            str.copy_char(read - 1, write++);
        }
    }

    if (write == str.length()) {
        return false;
    }

    str.truncate(write);

    return true;
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

} // namespace ddwaf::transformer
