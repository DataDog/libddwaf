// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "utf8.hpp"
#include <transformer/url_decode.hpp>
#include <utils.hpp>

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

namespace ddwaf::transformer {

namespace {

uint8_t fromHex(char c)
{
    if (ddwaf::isdigit(c)) {
        return (uint8_t)c - '0';
    }

    return (uint8_t)(c | 0x20) - 'a' + 0xa;
}

} // namespace

bool url_decode::transform_impl(lazy_string &str)
{
    std::size_t read = 0;
    bool readIIS = false;
    // Fast forward to a space or an hex encode char
    for (; read < str.length() && str.at(read) != '+'; ++read) {
        // Is there an hex encoded char?
        if (read + 2 < str.length() && str.at(read) == '%' && ddwaf::isxdigit(str.at(read + 1)) &&
            ddwaf::isxdigit(str.at(read + 2))) {
            break;
        }

        if (readIIS && read + 5 < str.length() && str.at(read) == '%' &&
            (str.at(read + 1) | 0x20) == 'u' && ddwaf::isxdigit(str.at(read + 2)) &&
            ddwaf::isxdigit(str.at(read + 3)) && ddwaf::isxdigit(str.at(read + 4)) &&
            ddwaf::isxdigit(str.at(read + 5))) {
            break;
        }
    }

    if (read >= str.length()) {
        return false;
    }

    std::size_t write = read;

    while (read < str.length()) {
        if (str.at(read) == '+') {
            str[write++] = ' ';
            read += 1;
        } else if (str.at(read) == '%') {
            // Normal URL encoding
            if (read + 2 < str.length() && ddwaf::isxdigit(str.at(read + 1)) &&
                ddwaf::isxdigit(str.at(read + 2))) {
                // TODO: we'll need to perform normalization here too
                const uint8_t highBits = fromHex(str.at(read + 1));
                const uint8_t lowBits = fromHex(str.at(read + 2));
                str[write++] = static_cast<char>(highBits << 4U | lowBits);
                read += 3;
            }
            // IIS-encoded wide characters
            else if (readIIS && read + 5 < str.length() && (str.at(read + 1) | 0x20) == 'u' &&
                     ddwaf::isxdigit(str.at(read + 2)) && ddwaf::isxdigit(str.at(read + 3)) &&
                     ddwaf::isxdigit(str.at(read + 4)) && ddwaf::isxdigit(str.at(read + 5))) {
                // Rebuild the codepoint from the hex
                const auto codepoint =
                    (uint16_t)(fromHex(str.at(read + 2)) << 12U | fromHex(str.at(read + 3)) << 8U |
                               fromHex(str.at(read + 4)) << 4U | fromHex(str.at(read + 5)));

                read += 6;

                if (codepoint <= 0x7f) {
                    str[write++] = static_cast<char>(codepoint);
                } else {
                    write += ddwaf::utf8::write_codepoint(codepoint, &str[write], read - write);
                }
            }
            // Fallback
            else {
                str[write++] = str.at(read++);
            }
        } else {
            str[write++] = str.at(read++);
        }
    }

    str.finalize(write);

    return true;
}

} // namespace ddwaf::transformer

// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
