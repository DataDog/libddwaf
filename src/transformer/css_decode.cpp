// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/css_decode.hpp"
#include "transformer/common/cow_string.hpp"
#include "transformer/common/utf8.hpp"
#include "utils.hpp"
#include <cstddef>
#include <cstdint>

namespace ddwaf::transformer {

bool css_decode::transform_impl(cow_string &str)
{
    // As soon as we find a backslash, we know the string will need to change somehow
    auto [found, read] = str.find('\\');
    if (!found) {
        return false;
    }

    size_t write = read;
    // Encoding specification: https://drafts.csswg.org/css-syntax/#escape-codepoint
    while (read < str.length()) {
        if (str.at(read) != '\\') {
            str[write++] = str.at(read++);
            continue;
        }

        read += 1;

        // Count the number of hex characters following the \, with a maximum of 6
        uint8_t count = 0;
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        while (count < 6 && read + count < str.length() && ddwaf::isxdigit(str.at(read + count))) {
            ++count;
        }

        // We need to decode
        if (count != 0U) {
            // Turn the hex sequence into an uint32_t
            uint32_t value = 0;
            while (count-- > 0) { value = (value << 4) | ddwaf::from_hex(str.at(read++)); }

            // Process the codepoint:
            // https://drafts.csswg.org/css-syntax/#consume-escaped-code-point
            write += utf8::write_codepoint(value, &str[write], read - write);

            // If a whitespace follow an escape, it's swallowed
            if (read < str.length() && ddwaf::isspace(str.at(read))) {
                ++read;
            }
        }
        // Simple escape
        else if (read < str.length()) {
            // A \n following a \\ is ignored
            auto next = str.at(read++);
            if (next != '\n') {
                str[write++] = next;
            }
        }
    }

    str.truncate(write);

    return true;
}

} // namespace ddwaf::transformer
