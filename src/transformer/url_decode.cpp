// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <cstdint>

#include "transformer/common/cow_string.hpp"
#include "transformer/common/utf8.hpp"
#include "transformer/url_decode.hpp"
#include "utils.hpp"

namespace ddwaf::transformer {

namespace {

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
/*
 * Bypasses are documented here:
 * https://www.postexplo.com/forum/ids-ips/network-based/764-ids-evasion-techniques-using-url-encoding
 */
bool url_decode_common(cow_string &str, bool read_iis)
{
    std::size_t read = 0;
    // Fast forward to a space or an hex encode char
    for (; read < str.length() && str.at(read) != '+'; ++read) {
        // Is there an hex encoded char?
        if (read + 2 < str.length() && str.at(read) == '%' && ddwaf::isxdigit(str.at(read + 1)) &&
            ddwaf::isxdigit(str.at(read + 2))) {
            break;
        }

        if (read_iis && read + 5 < str.length() && str.at(read) == '%' &&
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
                const uint8_t highBits = from_hex(str.at(read + 1));
                const uint8_t lowBits = from_hex(str.at(read + 2));
                str[write++] = static_cast<char>(highBits << 4U | lowBits);
                read += 3;
            }
            // IIS-encoded wide characters
            else if (read_iis && read + 5 < str.length() && (str.at(read + 1) | 0x20) == 'u' &&
                     ddwaf::isxdigit(str.at(read + 2)) && ddwaf::isxdigit(str.at(read + 3)) &&
                     ddwaf::isxdigit(str.at(read + 4)) && ddwaf::isxdigit(str.at(read + 5))) {

                // Rebuild the codepoint from the hex
                const auto codepoint =
                    (uint16_t)(from_hex(str.at(read + 2)) << 12U |
                               from_hex(str.at(read + 3)) << 8U | from_hex(str.at(read + 4)) << 4U |
                               from_hex(str.at(read + 5)));

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

    str.truncate(write);

    return true;
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
} // namespace

bool url_decode::transform_impl(cow_string &str) { return url_decode_common(str, false); }

bool url_decode_iis::transform_impl(cow_string &str)
{
    bool output = false;
    while (url_decode_common(str, true)) { output = true; }
    return output;
}

} // namespace ddwaf::transformer
