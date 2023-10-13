// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/js_decode.hpp"
#include "transformer/common/utf8.hpp"
#include "utils.hpp"

namespace ddwaf::transformer {

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
bool js_decode::transform_impl(cow_string &str)
{
    // As soon as we find a backslash, we know the string will need to change somehow
    auto [found, read] = str.find('\\');
    if (!found) {
        return false;
    }

    // There are three kinds of escape in JS:
    //   \X where X is an ASCII character (\n...) Can also escape normal ASCII characters
    //   \xYY where YY are one hex-encoded byte
    //   \uZZZZ where ZZZZ are a UTF-16 representation in hex, which we need to convert to
    //   UTF-8

    size_t write = read;
    while (read < str.length()) {
        if (str.at(read) != '\\') {
            str[write++] = str.at(read++);
            continue;
        }

        // Move past the backslash
        if (++read == str.length()) {
            str[write++] = '\\';
            continue;
        }

        auto escapeControl = str.at(read++);

        // Hex sequence, we're fairly permissive and invalid hex sequences are simply
        // ignored
        if (escapeControl == 'x') {
            if (read + 1 < str.length() && ddwaf::isxdigit(str.at(read)) &&
                ddwaf::isxdigit(str.at(read + 1))) {
                str[write++] =
                    (char)(ddwaf::from_hex(str.at(read)) << 4 | ddwaf::from_hex(str.at(read + 1)));
                read += 2;
            }
        }
        // UTF-16 :(
        // Convert UTF-16-BE to UTF-8
        else if (escapeControl == 'u') {
            // Check that the next four bytes are hex
            if (read + 3 < str.length() && ddwaf::isxdigit(str.at(read)) &&
                ddwaf::isxdigit(str.at(read + 1)) && ddwaf::isxdigit(str.at(read + 2)) &&
                ddwaf::isxdigit(str.at(read + 3))) {
                // Assume UTF-16 big endian as this is what Node is giving me
                const auto word = (uint16_t)(ddwaf::from_hex(str.at(read)) << 12 |
                                             ddwaf::from_hex(str.at(read + 1)) << 8 |
                                             ddwaf::from_hex(str.at(read + 2)) << 4 |
                                             ddwaf::from_hex(str.at(read + 3)));
                read += 4;

                // The word is a codepoint
                if (word < 0xd800 || word > 0xdbff) {
                    write += ddwaf::utf8::codepoint_to_bytes(word, &str[write]);
                }
                // The word is a surrogate, lets see if the other half is there
                else if (read + 5 < str.length() && str.at(read) == '\\' &&
                         str.at(read + 1) == 'u' &&
                         (ddwaf::isxdigit(str.at(read + 2)) && ddwaf::isxdigit(str.at(read + 3)) &&
                             ddwaf::isxdigit(str.at(read + 4)) &&
                             ddwaf::isxdigit(str.at(read + 5)))) {
                    const auto lowSurrogate = (uint16_t)(ddwaf::from_hex(str.at(read + 2)) << 12 |
                                                         ddwaf::from_hex(str.at(read + 3)) << 8 |
                                                         ddwaf::from_hex(str.at(read + 4)) << 4 |
                                                         ddwaf::from_hex(str.at(read + 5)));

                    // Correct surrogate sequence?
                    if (lowSurrogate >= 0xdc00 && lowSurrogate <= 0xdfff) {
                        // Good, now let's rebuild the codepoint
                        // Implementing the algorithm from
                        // https://en.wikipedia.org/wiki/UTF-16#Examples
                        const uint32_t codepoint =
                            0x10000U + ((word - 0xd800U) << 10U) + (lowSurrogate - 0xdc00U);
                        write += ddwaf::utf8::codepoint_to_bytes(codepoint, &str[write]);
                        read += 6;
                    }

                    // If it's wrong, let's ignore the first surrogate, and act as if we
                    // didn't see the second codepoint. THe next iteration will take care of
                    // it
                } else {
                    // Tried to make us write a half surrogate, write the error bytes
                    write += utf8::write_codepoint(word, &str[write], read - write);
                }
            }
        }
        // Escaped char
        else {
            char character = escapeControl;

            // We only check for cases where the next character isn't simply escaped. For
            // this case, copying the unmodified `character` is enough
            switch (character) {
            case 'a':
                character = '\a';
                break;
            case 'b':
                character = '\b';
                break;
            case 'f':
                character = '\f';
                break;
            case 'n':
                character = '\n';
                break;
            case 'r':
                character = '\r';
                break;
            case 't':
                character = '\t';
                break;
            case 'v':
                character = '\v';
                break;
            default:
                break;
            }

            str[write++] = character;
        }
    }

    str.truncate(write);

    return true;
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

} // namespace ddwaf::transformer
