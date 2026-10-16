// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <cstdint>

#include "cow_string.hpp"
#include "transformer/byte_scan.hpp"
#include "transformer/shell_unescape.hpp"
#include "utils.hpp"

namespace ddwaf::transformer {
/*
 * Reimplementing the cmdLine ModSecurity operator.
 * It is documented as follow:
 *
 * The cmdLine transformation function avoids this problem by manipulating the variable contend
 in the following ways:
 * 1. deleting all backslashes [\]
 * 2. deleting all double quotes ["]
 * 3. deleting all single quotes [']
 * 4. deleting all carets [^]
 * 5. deleting spaces before a slash [/]
 * 6. deleting spaces before an open parentesis [(]
 * 7. replacing all commas [,] and semicolon [;] into a space
 * 8. replacing all multiple spaces (including tab, newline, etc.) into one space
 * 9. transform all characters to lowercase
 */

namespace {

// The first character that requires a transformation
struct needs_unescape {
    // Removed characters (1, 2, 3 and 4)
    template <typename T> static auto removed(T c)
    {
        return byte_scan::eq(c, '\\') | byte_scan::eq(c, '"') | byte_scan::eq(c, '\'') |
               byte_scan::eq(c, '^');
    }

    // Removed characters and uppercase characters (9)
    template <typename T> static auto removed_or_upper(T c)
    { return removed(c) | byte_scan::in_range(c, 'A', 'Z'); }

    template <typename T> static auto space(T c)
    { return byte_scan::eq(c, ' ') | byte_scan::in_range(c, '\t', '\r'); }

    // The characters before which spaces are removed
    template <typename T> static auto space_or_terminator(T c)
    {
        return space(c) | byte_scan::eq(c, ',') | byte_scan::eq(c, ';') | byte_scan::eq(c, '(') |
               byte_scan::eq(c, '/');
    }

    // Characters we need to transform (7), or multiple spaces / space
    // equivalent characters (5, 6 and 8); these are only looked for when they
    // aren't the last character
    template <typename T> static auto match(T c, T next)
    {
        return removed_or_upper(c) | byte_scan::eq(c, ',') | byte_scan::eq(c, ';') |
               (space(c) & space_or_terminator(next));
    }

    static bool match_last(char c) { return removed_or_upper(c) != 0; }
};

#if defined(DDWAF_BYTE_SCAN_VECTOR)
// The characters that the transformation copies, lowercased, rather than
// removing or replacing them
struct copied_as_is {
    static byte_scan::bytes16 match(byte_scan::bytes16 c, byte_scan::bytes16 next)
    {
        // Whitespace other than ' ' is replaced, and ' ' is removed before
        // another space or a space terminator
        return needs_unescape::removed(c) | byte_scan::eq(c, ',') | byte_scan::eq(c, ';') |
               byte_scan::in_range(c, '\t', '\r') |
               (byte_scan::eq(c, ' ') & needs_unescape::space_or_terminator(next));
    }

    static byte_scan::bytes16 lowercase(byte_scan::bytes16 block)
    { return block | (byte_scan::in_range(block, 'A', 'Z') & byte_scan::bytes16::splat(0x20)); }
};

// A block and the character that follows it
constexpr std::size_t block_span = byte_scan::bytes16::size + 1;
#endif

} // namespace

bool shell_unescape::transform_impl(cow_string &str)
{
    // Fast forward, also implement readOnly
    uint64_t read = byte_scan::find_first_pair<needs_unescape>(str.data(), str.length());
    if (read == str.length()) {
        return false;
    }

    // The characters are read from the original string, the result is written
    // to a copy, which is only made on the first write (as for an empty result)
    const uint64_t length = str.length();
    const char *input = str.data();

    uint64_t write = read;
#if defined(DDWAF_BYTE_SCAN_VECTOR)
    // Where to look for the next block of characters that can be copied at once
    uint64_t next_block = read;
#endif
    // Actually perform the update
    for (; read < length; read += 1) {
#if defined(DDWAF_BYTE_SCAN_VECTOR)
        if (read == next_block) {
            next_block = length;
            for (; read + block_span <= length;
                 read += byte_scan::bytes16::size, write += byte_scan::bytes16::size) {
                const auto block = byte_scan::bytes16::load(input + read);
                const auto mask =
                    copied_as_is::match(block, byte_scan::bytes16::load(input + read + 1)).mask();
                if (mask.any()) {
                    next_block = read + mask.first() + 1;
                    break;
                }
                // If the string had already been copied, input is the copy:
                // as write <= read, this only overwrites characters already read
                copied_as_is::lowercase(block).store(str.modifiable_data() + write);
            }
        }
#endif

        const char c = input[read];

        // Remove 1, 2, 3 and 4
        if (c == '\\' || c == '"' || c == '\'' || c == '^') {
            continue;
        }
        if ((ddwaf::isspace(c)) || c == ',' || c == ';') {
            // We're doing all the space trimming here:
            //  We only copy the last space (or space terminator) character

            // First, we get rid of the case where we're on the last char: we will need to
            // write a space no matter what then
            if (read + 1 < length) {
                // Then, we find if the next char is space equivalent (7, 8) or a space
                // terminator (5, 6)
                auto next = input[read + 1];
                if (ddwaf::isspace(next) || next == ',' || next == ';' || next == '(' ||
                    next == '/') {
                    // We drop this character, the next iteration will take care of it
                    continue;
                }
            }

            // Otherwise, we write this last space!
            str[write++] = ' ';
        } else {
            // Handle upper case character
            str[write++] = ddwaf::tolower(c);
        }
    }

    if (write < str.length()) {
        str.truncate(write);
    }

    return true;
}

} // namespace ddwaf::transformer
